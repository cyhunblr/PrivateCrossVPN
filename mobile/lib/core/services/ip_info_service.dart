import 'package:dio/dio.dart';
import '../models/ip_info.dart';

class IpInfoService {
  IpInfoService._();
  static final IpInfoService instance = IpInfoService._();

  static const _cacheTtl = Duration(seconds: 30);

  final _dio = Dio(
    BaseOptions(
      connectTimeout: const Duration(seconds: 10),
      receiveTimeout: const Duration(seconds: 10),
    ),
  );

  IpInfo? _cache;
  DateTime? _cacheAt;
  Future<IpInfo?>? _inFlight;

  void clearCache() {
    _cache = null;
    _cacheAt = null;
  }

  Future<IpInfo?> fetch({bool forceRefresh = false}) async {
    if (!forceRefresh && _cache != null && _cacheAt != null) {
      final age = DateTime.now().difference(_cacheAt!);
      if (age <= _cacheTtl) {
        return _cache;
      }
    }

    if (_inFlight != null) {
      return _inFlight;
    }

    _inFlight = _fetchRemote();
    final result = await _inFlight;
    _inFlight = null;
    return result;
  }

  Future<IpInfo?> _fetchRemote() async {
    try {
      final resp =
          await _dio.get<Map<String, dynamic>>('https://ipinfo.io/json');
      if (resp.statusCode == 200 && resp.data != null) {
        final info = IpInfo.fromJson(resp.data!);
        _cache = info;
        _cacheAt = DateTime.now();
        return info;
      }
    } catch (_) {
      // Fallback to last known data to avoid flicker on transient network errors.
      return _cache;
    }
    return _cache;
  }
}
