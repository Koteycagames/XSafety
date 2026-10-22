/* Публичный конфиг Firebase. Ключ веб-приложения не является секретом:
 * доступ к данным ограничивают правила Realtime Database и Firebase Auth.
 * Адрес базы задаётся здесь, чтобы сайт работал на GitHub Pages без сборки.
 */
export const firebaseConfig = {
  apiKey: "AIzaSyDYQgJa7rlB_CAB4ywufavumzZrsS_pqNc",
  authDomain: "antivirus-1f569.firebaseapp.com",
  databaseURL: "https://antivirus-1f569-default-rtdb.firebaseio.com",
  projectId: "antivirus-1f569",
  storageBucket: "antivirus-1f569.firebasestorage.app",
  messagingSenderId: "780704862578",
  appId: "1:780704862578:web:a3f4eafe292a00ace8cdeb",
};

/* Владелец проекта: только этот адрес видит админ-панель. */
export const ADMIN_EMAIL = "Koteyca@gmail.com";
