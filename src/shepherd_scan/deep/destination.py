"""Where the deep check sends its package: Shepherd's drop box in Cloud Storage for Firebase.

These values only identify the Firebase project; they are not secrets. What anyone can do there
is decided by the project's storage rules (firebase/storage.rules in the repository): a scanner
can add one package to its own folder and nothing else, and only Shepherd can read. While they
are empty, the deep check is not offered.
"""

API_KEY: str = "AIzaSyB1xSYzQRp5Ghm2BX9VYi-7V5w7xH59pm8"
BUCKET: str = "shepdiagnostic.firebasestorage.app"
FOLDER = "uploads"
