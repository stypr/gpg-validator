if(window.crypto){
    (async () => {
        let checksumResultDOM = document.querySelector(".checksum-result");
        let keyserverResultDOM = document.querySelector(".keyserver-result");

        let pubkeyURL = {
            "root": ["https://harold.kim/keys/root.pub.asc", "/keys/root.pub.asc", "https://raw.githubusercontent.com/stypr/stypr/main/keys/root.pub.asc"],
            "general": ["https://harold.kim/keys/general.pub.asc", "/keys/general.pub.asc", "https://raw.githubusercontent.com/stypr/stypr/main/keys/general.pub.asc"],
            "confidential": ["https://harold.kim/keys/confidential.pub.asc", "/keys/confidential.pub.asc", "https://raw.githubusercontent.com/stypr/stypr/main/keys/confidential.pub.asc"]
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

        // compare with Ubuntu keyserver
        for(let purpose in keyserverURL){
            // get my public key
            let currMyPubkeyContent = pubkeyContent[purpose][0];
            // get my public key from keyserver
            keyserverResultDOM.innerText = `Fetching ${purpose} from keyserver...`;

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
                console.log(e);
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
    })()
}
