module starksign;

import std.algorithm;
import std.array;
import std.file;
import std.path;
import std.process;
import std.stdio;
import std.string;

import argparse;
import slf4d;
import server.developersession;
import sideload.application;
import sideload.certificateidentity;
import sideload.sign : sideloadSign;
import cli_frontend;

@(Command("starksign").Description("Register an iPhone and sign an IPA with a free Apple Developer account."))
struct StarkSignCommand {
    mixin LoginCommand;

    @(NamedArgument("udid").Description("iPhone UDID obtained by Stark Sign enrollment.").Required())
    string udid;

    @(NamedArgument("input").Description("Input IPA file.").Required())
    string input;

    @(NamedArgument("output").Description("Output signed IPA file.").Required())
    string output;

    int opCall() {
        enforce(isValidUdid(udid), "Invalid UDID.");
        enforce(exists(input) && isFile(input), "Input IPA not found.");

        auto config = systemConfigurationPath();
        scope data = initializeADI(config);
        scope adi = data.adi;
        scope device = data.device;
        auto account = login(device, adi);
        enforce(account !is null, "Apple ID login failed.");

        auto teams = account.listTeams().unwrap();
        enforce(teams.length > 0, "Apple account has no development team.");
        auto team = teams[0];

        auto devices = account.listDevices!iOS(team).unwrap();
        if (!devices.any!(d => d.deviceNumber.toUpper() == udid.toUpper())) {
            account.addDevice!iOS(team, "Stark Sign iPhone", udid).unwrap();
        }

        auto app = new Application(input);
        scope(exit) { if (app.tempPath.length && exists(app.tempPath)) rmdirRecurse(app.tempPath); }
        auto bundleId = app.bundleIdentifier();
        enforce(bundleId.length > 0, "IPA has no CFBundleIdentifier.");

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
        addProfile(bundleId, app.bundleName());
        foreach (sub; app.subBundles()) {
            if (sub.bundleDir.endsWith(".appex")) {
                addProfile(sub.bundleIdentifier(), sub.bundleName());
            }
        }

        auto identity = new CertificateIdentity(config, account);
        sideloadSign(app, identity, profiles, (double p) {}, true, team.teamId);

        auto out = absolutePath(output);
        auto outDir = dirName(out);
        if (!exists(outDir)) mkdirRecurse(outDir);
        if (exists(out)) remove(out);
        auto result = execute(["zip", "-qr", out, "Payload"], null, Config.none, 1024 * 1024, app.tempPath);
        enforce(result.status == 0 && exists(out), "Failed to package signed IPA: " ~ result.output);

        writeln("STARKSIGN_SUCCESS:", out);
        return 0;
    }
}

private bool isValidUdid(string value) {
    return value.length == 40 && value.all!(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}
