import 'package:flutter/material.dart';
import 'package:testapp/screens/auth/signup.dart';
import 'package:testapp/screens/todo_list.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark(),
      // home: const TodoListPage(),
      home: const SignupPage(),
       
    );
  }
}
