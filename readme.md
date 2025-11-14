# remove PyInstaller build + dist + spec outputs
rm -rf build dist __pycache__ *.spec

# clear your per-user app state (config, license, logs, exports)
rm -rf ~/.curator-finder

pip install -U pip wheel
pip install -r requirements.txt pyinstaller pywebview pynacl cffi



pyinstaller --noconfirm --name CuratorFinder \
  --noconsole \
  --add-data "dashboard.html:." \
  --add-data "app.env:." \
  --hidden-import _cffi_backend \
  --collect-submodules nacl \
  --collect-submodules cffi \
  desktop.py


pyinstaller --noconfirm --name CuratorFinder \
  --noconsole \
  --add-data "dashboard.html:." \
  --add-data ".env:." \
  --hidden-import _cffi_backend \
  --collect-submodules nacl \
  --collect-submodules cffi \
  desktop.py


rm -rf build dist *.spec
pyinstaller --noconfirm --name CuratorFinder \
  --noconsole \
  --add-data "dashboard.html:." \
  --add-data "app.env:." \
  --hidden-import _cffi_backend \
  --collect-submodules nacl \
  --collect-submodules cffi \
  desktop.py

---

rm -rf build dist __pycache__ *.spec

rm -rf ~/.curator-finder


python -m pip install -U pip wheel
python -m pip install -r requirements.txt pyinstaller


pyinstaller \
  --name CuratorFinder \
  --noconsole \
  --add-data "dashboard.html:." \
  desktop.py
