/*

            d8                           
    d88~\ _d88__ Y88b  / 888-~88e  888-~\
   C888    888    Y888/  888  888b 888   
    Y88b   888     Y8/   888  8888 888   
     888D  888      Y    888  888P 888   
   \_88P   "88_/   /     888-_88"  888   
                 _/      888             

            Copyright https://harold.kim/
            Respective copyrights apply.


This script is used to validate the network connection and GPG keys of https://harold.kim/.
This script reduces down some attack surfaces, but it still posesses some existing issues such as:

1. potential MitM attacks on HTTPS.
    * There is no way for JavaScript to interact and detect bogus certificates.
    * Could be mitigated by Common Sense 2022.
    * Use https://crt.sh/?q=gpg.harold.kim to cross-check with CT logs.
    * Check the website from PCs and Mobile networks with different ISPs/Carriers/VPNs.

2. GitHub Page gets compromised. or Malicious actor is GitHub itself
    * GitHub Security Team might notice if some breach ever happens.
    * But there were security reports which successfully attacked GitHub Pages.
    * You can perhaps send mail to the person directly or meet physically to confirm the fingerprint.

TODO:
1. Verify signed commits of the current repository

*/

(async () => {
    /*
        Validating Network Connections

        1. Query DoH over Cloudflare and Google DNS
        2. Check if validator is resolved to GitHub Pages
        3. Check if validator matches with hostname, with https protocol
    */
    const validateNetwork = async () => {
        let validatorHost = "gpg.harold.kim.";
        let resolveHost = "stypr.github.io.";
        let currLocationHost = window.location.hostname;
        let networkResultDOM = document.querySelector(".network-result");

        let dohURL = [
            "https://1.1.1.1/dns-query",
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve"
        ];
        let networkResult = {
            "doh": [],
            "dohCheck": -1,
        };

        for(let dohHost of dohURL){
            networkResultDOM.innerText = `Fetching DoH resolvers...`;
            networkResult.doh.push(
                await fetch(
                    `${dohHost}?name=${validatorHost}&type=CNAME&do=1`,
                    {
                        cache: "no-store",
                        headers: {"accept": "application/dns-json"}
                    }
                )
                .then(r => r.json())
                .then(r => {
                    return (
                        r.Status == 0 && // NOERROR
                        r.RA == 1 &&  // DNSSEC Enabled
                        r.Answer[0].data == resolveHost // Resolved to GitHub Pges
                    )
                })
                .catch(r => {
                    return false;
                })
            );
        }
        networkResult.dohCheck = await (arr => arr.every(v => v && v === true))(networkResult.doh);
        networkResult.hostCheck = (currLocationHost+"." === validatorHost && self.location.protocol === "https:");

        networkResultDOM.innerHTML = networkResult.dohCheck === true && ` <font color=green>Resolver PASS</font> /` || ` <font color=red>Resolver FAIL</font> /`;
        networkResultDOM.innerHTML += networkResult.hostCheck === true && ` <font color=green>HostCheck PASS</font> /` || ` <font color=red>HostCheck FAIL</font> /`;

        networkResultDOM.innerHTML = networkResultDOM.innerHTML.slice(0, -1);
    };

    /*
        Validating GPG Keys

        1. Validator crawls keys from stypr/stypr, stypr/gpg-validator and https://harold.kim respectively
        2. Validator checks if all keys from the same group are matching to each other
        3. Validator checks if cheksum of each key from the group matches with the predefined sha512sum
        4. Validator crawls keys from OpenPGP keyserver
        5. Validator checks if fingerprints, group order, and key id match with the crawled keys from step (1).
    */
     const validateKeys = async () => {
        let checksumResultDOM = document.querySelector(".checksum-result");
        let keyserverResultDOM = document.querySelector(".keyserver-result");

        let pubkeyURL = {
            "root": [
                "https://harold.kim/keys/root.pub.asc",
                "https://raw.githubusercontent.com/stypr/stypr/main/keys/root.pub.asc",
                "/keys/root.pub.asc"
            ],
            "general": [
                "https://harold.kim/keys/general.pub.asc",
                "https://raw.githubusercontent.com/stypr/stypr/main/keys/general.pub.asc",
                "/keys/general.pub.asc"
            ],
            "confidential": [
                "https://harold.kim/keys/confidential.pub.asc",
                "https://raw.githubusercontent.com/stypr/stypr/main/keys/confidential.pub.asc",
                "/keys/confidential.pub.asc"
            ]
        };

        let keyserverURL = {
            "root": "https://keys.openpgp.org/vks/v1/by-fingerprint/2064FF9330111A9094B319DAB43975C459ED7A46",
            "general": "https://keys.openpgp.org/vks/v1/by-fingerprint/4F3D0B5DA557FC3535ACEE3F87C4CD66A509906B",
            "confidential": "https://keys.openpgp.org/vks/v1/by-fingerprint/9C1D006897CD998081C7A457F01CD491240E43A6"
        };

        let pubkeyContent = {
            "root": [],
            "general": [],
            "confidential": []
        };

        let sha512sum = {
            "root": "b3a0dfda3d93bba7798190c67d39613ecf332330aeebcee80a4f816dbbea6e685fe69bb45baa9eb2a55bcabcbfc38fc19ab59978b687efeb990b22acdd117ba2",
            "general": "a55bb899a0e2dc1ed26b4d927d3823e357ba4f2b3b7fd83d9a1f6a24b16039641b02c4bb0c0e8700ea4a56f4585a937fe2de6e02d38a42177b1dc14dac9f2b80",
            "confidential": "142ccfcfb7046cc2f532a865ab2cac827034f6730be354daed1e5b7f670254bf856400bcc66ce8bdf524f3ad4acfadcc4b53a46bb9be94a7fc7be68a11527fcc",
        };

        let pubkeyResult = {
            "root": [-1, -1],
            "general": [-1, -1],
            "confidential": [-1, -1],
        };

        checksumResultDOM.innerText = `Loading...`;
        keyserverResultDOM.innerText = `Loading...`;

        // compare checksums, compare if keys are matching
        for(let purpose in pubkeyURL){
            // check if pubkey matches with other files
            let currPubkeyURL = pubkeyURL[purpose];
            let currResult = [];
            for(let pubkey of currPubkeyURL){
                checksumResultDOM.innerText = `Fetching ${purpose}...`;
                keyserverResultDOM.innerText = `Fetching ${purpose}...`;
                await fetch(pubkey, {cache: "no-store"})
                    .then(r => r.text())
                    .then(r => {
                        // push content and checksums to array
                        pubkeyContent[purpose].push(r);
                        currResult.push(sha512(r));
                    })
                    .catch(r => {
                        pubkeyContent[purpose].push("");
                        currResult.push("");
                    });
            }
            keyserverResultDOM.innerText = `Loading...`;
            // compare if all keys contents and checksums match
            checksumResultDOM.innerText = `Comparing checksums of ${purpose}...`;
            let checksumResult = await (arr => arr.every(v => v && v === arr[0]))(currResult);
            let contentResult  = await (arr => arr.every(v => v && v === arr[0]))(pubkeyContent[purpose]);
            pubkeyResult[purpose][0] = checksumResult && contentResult && currResult[0] === sha512sum[purpose];
        }
        checksumResultDOM.innerText = `Loading...`;

        // compare with OpenPGP keyserver
        for(let purpose in keyserverURL){
            keyserverResultDOM.innerText = `Fetching ${purpose} from keyserver...`;
            // get my public key
            let currMyPubkeyContent = pubkeyContent[purpose][0];
            // get my public key from keyserver
            let currKeyserverContent = await fetch(keyserverURL[purpose], {cache: "no-store"})
                .then(r => r.text())
                .then(r => r)
                .catch(r => "");

            // compare them!
            try{
                let currMyPublicKey = await openpgp.readKey({ armoredKey: currMyPubkeyContent });
                let currKeyserverPublicKey = await openpgp.readKey({ armoredKey: currKeyserverContent });

                keyserverResultDOM.innerText = `Comparing ${purpose} from keyserver...`;
                pubkeyResult[purpose][1] = (
                    currMyPublicKey.keyPacket.keyID.bytes === currKeyserverPublicKey.keyPacket.keyID.bytes &&
                    JSON.stringify(currMyPublicKey.keyPacket.fingerprint) === JSON.stringify(currKeyserverPublicKey.keyPacket.fingerprint) &&
                    JSON.stringify(currMyPublicKey.keyPacket.publicParams.Q) === JSON.stringify(currKeyserverPublicKey.keyPacket.publicParams.Q) &&
                    JSON.stringify(currMyPublicKey.keyPacket.publicParams.oid.oid) === JSON.stringify(currKeyserverPublicKey.keyPacket.publicParams.oid.oid)
                );
            }catch(e){
                pubkeyResult[purpose][1] = false;
            }
        }

        // populate result
        checksumResultDOM.innerHTML = ``;
        keyserverResultDOM.innerHTML = ``;
        for(let purpose in keyserverURL){
            checksumResultDOM.innerHTML += pubkeyResult[purpose][0] === true && ` <font color=green>${purpose} PASS</font> /` || ` <font color=red>${purpose} FAIL</font> /`;
            keyserverResultDOM.innerHTML += pubkeyResult[purpose][1] === true && ` <font color=green>${purpose} PASS</font> /` || ` <font color=red>${purpose} FAIL</font> /`;
        };
        checksumResultDOM.innerHTML = checksumResultDOM.innerHTML.slice(0, -1);
        keyserverResultDOM.innerHTML = keyserverResultDOM.innerHTML.slice(0, -1);
    };

    validateKeys();
    validateNetwork();
})();
