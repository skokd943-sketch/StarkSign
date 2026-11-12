module starksign;

import std.algorithm;
import std.array;
import std.exception;
import std.file;
import std.path;
import std.process;
import std.stdio;
import std.string;
import std.typecons;

import argparse;
import provision;
import slf4d;
import app;
import server.appleaccount : Success, ReloginNeeded, AppleLoginError;
import server.developersession;
import sideload.application;
import sideload.certificateidentity;
import sideload.sign : sideloadSign;

extern(C) char* getpass(const(char)* prompt);

private string readApplePassword(string prompt) {
    return fromStringz(cast(immutable) getpass(prompt.toStringz()));
}

private DeveloperSession loginApple(Device device, ADI adi) {
    write("Apple ID: ");
    auto appleId = readln().chomp();
    auto password = readApplePassword("Password: ");
    return DeveloperSession.login(device, adi, appleId, password,
        (sendCode, submitCode) {
            sendCode();
            string code;
            do {
                write("A code has been sent to your devices, please type it here (type `resend` to resend one): ");
                code = readln().chomp();
                if (code == "resend") {
                    sendCode();
                    continue;
                }
            } while (submitCode(code).match!(
                (Success _) => false,
                (ReloginNeeded _) => false,
                (AppleLoginError _) => true
            ));
        }
    ).match!(
        (DeveloperSession session) => session,
        (AppleLoginError error) {
            throw new Exception(error.description);
        }
    );
}

@(Command("starksign").Description("Register an iPhone and sign an IPA with a free Apple Developer account."))
struct StarkSignCommand {
    @(NamedArgument("udid").Description("iPhone UDID obtained by Stark Sign enrollment.").Required())
    string udid;

    @(NamedArgument("input").Description("Input IPA file.").Required())
    string input;

    @(NamedArgument("output").Description("Output signed IPA file.").Required())
    string output;

    int opCall() {
        enforce(isValidUdid(udid), "Invalid UDID.");
        enforce(exists(input) && isFile(input), "Input IPA not found.");

        string config = environment.get("SIDELOADER_CONFIG_DIR").orDefault("/tmp/starksign-account");
        if (!(exists(buildPath(config,"lib","libstoreservicescore.so")) && exists(buildPath(config,"lib","libCoreADI.so")))) {
            mkdirRecurse(config);
            enforce(downloadAndInstallDeps(config, (float progress) => false), "Failed to download Apple ADI libraries.");
        }
        scope data = app.initializeADI(config);
        scope adi = data.adi;
        scope device = data.device;
        auto account = loginApple(device, adi);

        auto teams = account.listTeams().unwrap();
        enforce(teams.length > 0, "Apple account has no development team.");
        auto team = teams[0];

        auto devices = account.listDevices!iOS(team).unwrap();
        if (!devices.any!(d => d.deviceNumber.toUpper() == udid.toUpper())) {
            account.addDevice!iOS(team, "Stark Sign iPhone", udid).unwrap();
        }

        auto appBundle = new Application(input);
        scope(exit) { if (appBundle.tempPath.length && exists(appBundle.tempPath)) rmdirRecurse(appBundle.tempPath); }
        auto bundleId = appBundle.bundleIdentifier();
        enforce(bundleId.length > 0, "IPA has no CFBundleIdentifier.");

        auto identity = new CertificateIdentity(config, account);
        if (identity.keyFile.length && exists(identity.keyFile)) chmod(identity.keyFile, 0o600);

        ProvisioningProfile[string] profiles;
        void addProfile(string identifier, string displayName) {
            auto ids = account.listAppIds!iOS(team).unwrap();
            auto matching = ids.appIds.filter!(a => a.identifier == identifier).array();
            if (matching.length == 0) {
                enforce(ids.availableQuantity > 0, "Free Apple account has reached its App ID limit.");
                account.addAppId!iOS(team, identifier, displayName).unwrap();
                ids = account.listAppIds!iOS(team).unwrap();
                matching = ids.appIds.filter!(a => a.identifier == identifier).array();
            }
            enforce(matching.length > 0, "Apple did not create App ID: " ~ identifier);
            profiles[identifier] = account.downloadTeamProvisioningProfile!iOS(team, matching[0]).unwrap();
        }
        addProfile(bundleId, appBundle.bundleName());
        foreach (sub; appBundle.subBundles()) {
            if (sub.bundleDir.endsWith(".appex")) addProfile(sub.bundleIdentifier(), sub.bundleName());
        }

        sideloadSign(appBundle, identity, profiles, (double progress) {}, true, team.teamId);

        auto out = absolutePath(output);
        auto outDir = dirName(out);
        if (!exists(outDir)) mkdirRecurse(outDir);
        if (exists(out)) remove(out);
        auto result = executeShell("cd " ~ appBundle.tempPath ~ " && zip -qr " ~ out ~ " Payload");
        enforce(result.status == 0 && exists(out), "Failed to package signed IPA: " ~ result.output);

        writeln("STARKSIGN_SUCCESS:", out);
        return 0;
    }
}

private bool isValidUdid(string value) {
    return value.length == 40 && value.all!(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}
