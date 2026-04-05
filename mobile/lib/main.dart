import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'ui/screens/home_screen.dart';
import 'ui/screens/profile_edit_screen.dart';
import 'ui/screens/settings_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ProviderScope(child: PrivateCrossVPNApp()));
}

final _router = GoRouter(
  routes: [
    GoRoute(path: '/', builder: (_, __) => const HomeScreen()),
    GoRoute(path: '/settings', builder: (_, __) => const SettingsScreen()),
    GoRoute(
      path: '/profile/new',
      builder: (_, __) => const ProfileEditScreen(),
    ),
    GoRoute(
      path: '/profile/edit/:name',
      builder: (_, state) =>
          ProfileEditScreen(profileName: state.pathParameters['name']),
    ),
  ],
);

class PrivateCrossVPNApp extends StatelessWidget {
  const PrivateCrossVPNApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp.router(
        title: 'PrivateCrossVPN',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: Colors.blue,
            brightness: Brightness.dark,
          ),
          useMaterial3: true,
        ),
        routerConfig: _router,
      );
}
