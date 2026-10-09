python -m venv my_sms_proxy/.venv
my_sms_proxy/.venv/scripts/activate
python.exe -m pip install --upgrade pip
python -c "import sys; print(sys.executable)"
>C:\code\600_manyfaces\my_sms_proxy\.venv\scripts\python.exe
python -m pip install -r my_sms_proxy\requirements.txt
python -c "import importlib.metadata; print(importlib.metadata.version('flask'))"
3.1.3
python my_sms_proxy\app.py