# Server app catalog

Place `.ipa` files directly in this folder. Railway reads each IPA during deployment and extracts the app name, version, bundle identifier and app icon automatically. The files are shown in Stark Sign under **Приложения → На сервере**.

Notes:
- Use valid, unencrypted iOS IPA files.
- GitHub rejects individual files larger than 100 MB; large IPAs need Git LFS or external binary storage.
- A Git push triggers Railway redeployment when auto-deploy is enabled.
