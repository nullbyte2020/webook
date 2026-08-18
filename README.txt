Kimiko Webook Booking Assistant
================================

متطلبات التشغيل:
- Windows 10 أو أحدث (64-bit)
- اتصال إنترنت نشط (لتحميل Node.js والمكتبات والمتصفح)
- صلاحيات Administrator عند التثبيت

طريقة التثبيت (ملف EXE):
1. أغلق أي نسخة قديمة من البرنامج.
2. اضغط مرتين على KimikoWebookBot-Setup.exe.
3. اقبل صلاحيات Administrator عند الطلب.
4. انتظر حتى ينتهي التثبيت. سيتم:
   - تحميل Node.js تلقائياً إذا لم يكن موجوداً.
   - تثبيت جميع المكتبات المطلوبة من الإنترنت.
   - تثبيت متصفح Chromium ومكتباته اللازمة لعرض الشارت.
   - إنشاء اختصار على سطح المكتب وقائمة Start.
   - حذف اختصارات النسخ القديمة تلقائياً.

طريقة التثبيت (ملف ZIP):
1. فك ضغط الملف KimikoWebookBot.zip في أي مجلد.
2. اضغط كليك يمين على RUN-AS-ADMIN.bat واختر "Run as administrator".
3. انتظر حتى ينتهي التثبيت.

طريقة التشغيل:
- اضغط مرتين على اختصار "Kimiko Webook Booking" على سطح المكتب.
- سيتم فتح المتصفح تلقائياً على http://localhost:3456

ملاحظات:
- لا تحذف مجلد التثبيت داخل Program Files أو %LOCALAPPDATA%\KimikoWebookBot بعد التثبيت.
- إذا واجهت أي مشكلة، شغّل المثبت مرة أخرى لإعادة التثبيت/التحديث.
- إذا ظهرت مشكلة في تحميل الشارت، تأكد من تثبيت Visual C++ Redistributable:
  https://aka.ms/vs/17/release/vc_redist.x64.exe

---

System Requirements:
- Windows 10 or newer (64-bit)
- Active internet connection (to download Node.js, libraries, and browser)
- Administrator rights during installation

Installation (EXE):
1. Close any old version of the app.
2. Double-click KimikoWebookBot-Setup.exe.
3. Accept Administrator rights when prompted.
4. Wait for the installer to finish. It will automatically:
   - Download Node.js if not already installed.
   - Install all required npm packages from the internet.
   - Install the Chromium browser and its system dependencies so the chart renders.
   - Create a desktop shortcut and Start Menu entry.
   - Remove old shortcuts from previous versions.

Installation (ZIP):
1. Extract KimikoWebookBot.zip to any folder.
2. Right-click RUN-AS-ADMIN.bat and choose "Run as administrator".
3. Wait for the installer to finish.

Running:
- Double-click the "Kimiko Webook Booking" shortcut on your desktop.
- Your browser will open automatically at http://localhost:3456

Notes:
- Do not delete the installation folder at Program Files or %LOCALAPPDATA%\KimikoWebookBot.
- If you encounter issues, run the installer again to repair/update.
- If the chart does not load, install the Visual C++ Redistributable:
  https://aka.ms/vs/17/release/vc_redist.x64.exe
