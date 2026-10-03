import 'dart:developer' as developer;

import 'package:cookie_jar/cookie_jar.dart';
import 'package:dio/dio.dart';

/// 阿里云网站防火墙（ESA / WAF）的人机验证求解器。
///
/// 论坛遭遇攻击后会提升防御等级：普通客户端会收到一段带 `arg1` 的混淆
/// 脚本，浏览器执行脚本写入 `acw_sc__v2` Cookie 后才会返回真正的页面。
/// App 没有 JS 引擎，因此在本地复刻同一算法算出该 Cookie，再带上 Cookie
/// 重试请求，从而无需内置浏览器也能正常访问。
class AntiBotChallenge {
  AntiBotChallenge._();

  static final RegExp _arg1Pattern = RegExp(r"arg1\s*=\s*'([0-9A-Fa-f]+)'");

  /// 验证脚本中的固定置换表（对应混淆代码里的 `m` 数组）。
  static const List<int> _permutation = <int>[
    0xf, 0x23, 0x1d, 0x18, 0x21, 0x10, 0x1, 0x26, 0xa, 0x9, //
    0x13, 0x1f, 0x28, 0x1b, 0x16, 0x17, 0x19, 0xd, 0x6, 0xb, //
    0x27, 0x12, 0x14, 0x8, 0xe, 0x15, 0x20, 0x1a, 0x2, 0x1e, //
    0x7, 0x4, 0x11, 0x5, 0x3, 0x1c, 0x22, 0x25, 0xc, 0x24, //
  ];

  /// 异或运算使用的固定密钥。
  static const String _xorKey = '3000176000856006061501533003690027800375';

  /// 判断响应体是否为阿里云人机验证页。
  static bool isChallenge(String? body) {
    if (body == null || body.isEmpty) return false;
    // 真实论坛页面通常数十 KB，验证页只有 4KB 左右，先按体积快速过滤。
    if (body.length > 20000) return false;
    return body.contains('acw_sc__v2') && _arg1Pattern.hasMatch(body);
  }

  /// 从验证页中解出 `acw_sc__v2` 的值，解析失败返回 null。
  static String? solve(String? body) {
    if (body == null) return null;
    final match = _arg1Pattern.firstMatch(body);
    if (match == null) return null;
    return solveArg1(match.group(1)!);
  }

  /// 复刻验证脚本：先按置换表重排 arg1，再与固定密钥逐字节异或。
  static String solveArg1(String arg1) {
    final slots = List<String>.filled(_permutation.length, '');
    for (var i = 0; i < arg1.length; i++) {
      final char = arg1[i];
      for (var j = 0; j < _permutation.length; j++) {
        if (_permutation[j] == i + 1) slots[j] = char;
      }
    }
    final unsboxed = slots.join();
    final limit =
        unsboxed.length < _xorKey.length ? unsboxed.length : _xorKey.length;
    final buffer = StringBuffer();
    for (var i = 0; i + 1 < limit; i += 2) {
      final left = int.parse(unsboxed.substring(i, i + 2), radix: 16);
      final right = int.parse(_xorKey.substring(i, i + 2), radix: 16);
      buffer.write((left ^ right).toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }
}

/// 自动识别人机验证、写入 Cookie 并重试的 Dio 拦截器。
class AntiBotInterceptor extends Interceptor {
  AntiBotInterceptor({
    required this.jar,
    required this.dio,
    this.maxRetries = 3,
  });

  final CookieJar jar;
  final Dio dio;
  final int maxRetries;

  static const String _retryKey = 'mtforum_antibot_retries';

  @override
  Future<void> onResponse(
    Response<dynamic> response,
    ResponseInterceptorHandler handler,
  ) async {
    final options = response.requestOptions;
    final attempts = (options.extra[_retryKey] as int?) ?? 0;
    final body = response.data is String ? response.data as String : null;
    final challenged = AntiBotChallenge.isChallenge(body);
    // 被拦截时除了验证页，也会出现 403 + 空响应体的情况，一并重试。
    final blocked = response.statusCode == 403 && (body == null || body.isEmpty);

    if ((!challenged && !blocked) || attempts >= maxRetries) {
      handler.next(response);
      return;
    }

    final uri = options.uri;
    // 必须先把验证响应下发的 acw_tc / cdn_sec_tc 等 Cookie 收进 jar，
    // 否则服务端会视为新会话而继续下发验证页。
    final setCookies = response.headers['set-cookie'];
    if (setCookies != null && setCookies.isNotEmpty) {
      final parsed = <Cookie>[];
      for (final value in setCookies) {
        try {
          parsed.add(Cookie.fromSetCookieValue(value));
        } catch (_) {
          // 个别 Cookie 字段格式特殊，忽略即可。
        }
      }
      if (parsed.isNotEmpty) {
        await jar.saveFromResponse(uri, parsed);
      }
    }

    final solved = AntiBotChallenge.solve(body);
    if (solved == null || solved.isEmpty) {
      handler.next(response);
      return;
    }
    await jar.saveFromResponse(uri, <Cookie>[
      Cookie('acw_sc__v2', solved)..path = '/',
    ]);

    options.extra[_retryKey] = attempts + 1;
    await _attachCookies(options, uri);
    try {
      final retried = await dio.fetch<dynamic>(options);
      handler.resolve(retried);
    } catch (error, stack) {
      // 重试失败时交回原始响应，由业务层按原有逻辑报错。
      developer.log(
        'anti-bot retry failed: $error',
        name: 'AntiBotInterceptor',
        error: error,
        stackTrace: stack,
      );
      handler.next(response);
    }
  }

  /// 部分 Dio（例如桌面版请求）没有挂 CookieManager，需要手动把 jar 里的
  /// Cookie 合并进请求头；使用追加而非覆盖，避免丢掉已有的登录 Cookie。
  Future<void> _attachCookies(RequestOptions options, Uri uri) async {
    final cookies = await jar.loadForRequest(uri);
    if (cookies.isEmpty) return;
    final existing = options.headers['cookie'] ?? options.headers['Cookie'];
    final parts = <String>[
      if (existing is String && existing.trim().isNotEmpty) existing.trim(),
      ...cookies.map((cookie) => '${cookie.name}=${cookie.value}'),
    ];
    options.headers['cookie'] = parts.join('; ');
  }
}