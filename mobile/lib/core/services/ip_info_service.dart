import 'package:dio/dio.dart';
import '../models/ip_info.dart';

class IpInfoService {
  IpInfoService._();
  static final IpInfoService instance = IpInfoService._();

  final _dio = Dio(BaseOptions(connectTimeout: const Duration(seconds: 10)));

  Future<IpInfo?> fetch() async {
    try {
      final resp = await _dio.get<Map<String, dynamic>>('https://ipinfo.io/json');
      if (resp.statusCode == 200 && resp.data != null) {
        return IpInfo.fromJson(resp.data!);
      }
    } catch (_) {}
    return null;
  }
}
