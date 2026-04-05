class IpInfo {
  final String ip;
  final String city;
  final String region;
  final String country;
  final String org;
  final String timezone;

  const IpInfo({
    required this.ip,
    required this.city,
    required this.region,
    required this.country,
    required this.org,
    required this.timezone,
  });

  factory IpInfo.fromJson(Map<String, dynamic> j) => IpInfo(
        ip: (j['ip'] as String?) ?? '',
        city: (j['city'] as String?) ?? '',
        region: (j['region'] as String?) ?? '',
        country: (j['country'] as String?) ?? '',
        org: (j['org'] as String?) ?? '',
        timezone: (j['timezone'] as String?) ?? '',
      );

  String get location {
    final parts = [city, region, country].where((s) => s.isNotEmpty).toList();
    return parts.isEmpty ? 'Unknown' : parts.join(', ');
  }
}
