---
title: ""
linkTitle: "Changelog"
weight: 5
menu: false
type: docs
---

<script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js" integrity="sha384-DfXdz2htPH0lsSSs5nCTpuj/zy4C+OGpamoFVy38MVBnE+IbbVYUew+OrCXaRkfj" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-Fy6S3B9q64WdZWQUiU+q4/2Lc9npb8tCaSX9FK7E8HnRr0Jz8D6OP9dO5Vg3Q9ct" crossorigin="anonymous"></script>

<div class="changelog-container card card-body">
<div class="h3 changelog-release">• unreleased / untagged</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#serut0" aria-expanded="false" aria-controls="serut0">
<div class="h4"> <!-- 0 -->🚀 Features <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="serut0">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1555d0897b0f74e930737e31aa7edaafc074eac7">1555d08</a> Drop obsolete RTX_BUFFER_SIZE and usize_max</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/abdbf8f3da96e117fd8a52573a41d14c5f74e7a8">abdbf8f</a> Cleanup, document and add tests</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/77760d71df101ed71066f74626cdee506bcdd8c6">77760d7</a> Use mio::Token based polling</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/53e560191f7d76986f17757fe105dad5ae2636c6">53e5601</a> Close API connections after error</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/594f894206db06b19a0b35356ab6dcfc9a18ff09">594f894</a> AddPskBroker endpoint</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/24eebe29a1f0b46fae1d36cae2a847b9da621b6e">24eebe2</a> AddListenSocket endpoint</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1d2fa7d038ed5923dc77ac6e8b8e5bfed3535965">1d2fa7d</a> API Feature – Add server keys via API</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/edf1e774c1357218c8a5ccba97051841b96b30d9">edf1e77</a> SupplyKeypair endpoint</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/065b0fcc8ac24b34ef5acfc614853099dd463956">065b0fc</a> Add enable_wg_broker feature using MioBrokerClient</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1853e0a3c0fe52561bca0b5dd38016cd036eafdb">1853e0a</a> Add test case and check fd value</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/245d4d1a0fa631b52b7a1aeb2589228b1cbf03d7">245d4d1</a> Add tests for util file.rs</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/6d47169a5cee6319ebf419e375635e1fac2d48fc">6d47169</a> Set CLOEXEC flag on claimed fds and mask them</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/4bcd38a4ea033ec35a91faf2d07499fc4130cd59">4bcd38a</a> Infrastructure for the Rosenpass API</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/730a03957ade3b1bc05daf6959e6997586289d78">730a039</a> A variety of utilities in preparation for implementing the API</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/ea071f536376bc790197ff7f598f676b8ab9dc82">ea071f5</a> Convenience functions and traits to automatically handle ErrorKind::{Interrupt, WouldBlock}</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/3063d3e4c2dfa6b3d1eb68f6b176a776e4ff95a7">3063d3e</a> Convenience traits to get the ErrorKind of an io error for match clauses</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1bf0eed90a8ed2984a6d6dcf016713fe63cc40d3">1bf0eed</a> Convenience function to just call a function</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/99ac3c0902485a6879b6aa0e5f13712819f6ef5b">99ac3c0</a> Experimental support for encryption using libcrux</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/d0a6e99a1f6bd3271bfe40b95728e120fb838572">d0a6e99</a> Regression CI based on misc/generate_configs.py</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7a4f70018671fb03ff82ea980cc1da970ab66485">7a4f700</a> Improved memfd-secret allocation (#347)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/c1abfbfd14e4f596d7840c4ac65d5867626cba9c">c1abfbf</a> Add wireguard-broker interface in AppServer (#303)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/2bac9913059f1eb7dd5008e9a6585e35445808c5">2bac991</a> Merge from dev/broker-architecture, fixes, test</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/4bb31537619295229182503c0c94ce279fa59914">4bb3153</a> Change base64 to base64ct crate (#295)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/cc7e8dc5100758800b051c37ee0362ba5495b926">cc7e8dc</a> Implement rp tool in Rust (#235)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/ca972e8b70c62ff7c07f495fcbd05c2f44ac2a81">ca972e8</a> Remove libsodium</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/2fa0a2a72ab32624fe6e9ee5282e6aa81c1a513c">2fa0a2a</a> Use core::hint::black_box in rosenpass_constant_time::xor</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/b6203683fc968ad47de6839221fa862feca72f95">b620368</a> Migrate away from sodium blake2b towards the rust crypto implementation</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e0f75ab97efe3ef241d1bb7cdf83e092d64c5d27">e0f75ab</a> Use xchacha implementation from rust crypto instead of sodium</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/0789c60602e8bb5cb83283cf9c04e596eee1001e">0789c60</a> Use chacha implementation from rust crypto instead of sodium</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/85c447052e5bd7e3845815685b1ce45318690025">85c4470</a> Migrate to memsec</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/b2a64ed17a30d835b1bb9bd9bc1a9ac21fe72780">b2a64ed</a> Add INITIATOR_TEST and RESPONDER_TEST macros</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/91da0dfd2da54c3b3fa960475e90e9a36de03561">91da0df</a> Identity hiding in two stage process</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/4a170b19830c2df80c6031b73adce876df5b9947">4a170b1</a> Add inital identity hiding code to proverif</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/eb76179dc4f6ea5ee3780a538ddf25b6ab6e8183">eb76179</a> Add format_rustcode.sh script</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/3a0ebd2cbc9f873f2f33624dbb108650eaa5095c">3a0ebd2</a> Add fuzzing for libsodium allocator</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/d45e24e9b6e1bad5c02a97a9101572ece5baef35">d45e24e</a> Move lenses into library</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/101c9bf4b34e43f997d831d165dee8783ecdbf76">101c9bf</a> Add an internal library for guaranteed results</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/5448cdc565f5f5f0fc964dbfc2696e3184323c82">5448cdc</a> Use the rand crate for random values instead of sodium</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/77cd8a9fd107f6fa11bb945a3111d0bd08bb7e85">77cd8a9</a> Move prftree into ciphers crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/70fa9bd6d704a5c145b36bce91c6da3196bbbc6e">70fa9bd</a> Wrap sodium_malloc as a custom allocator</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/85a61808de0abd14f4a7cb243f74fd4e82e1b0c0">85a6180</a> Use the zeroize crate for zeroization</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/d539be314252dd9a87aa432742b88dc347f556c3">d539be3</a> Rosenpass-to for nicely handling destination parameters</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a49254a021bef0b8666b55097fe74b185fede4ae">a49254a</a> Add initial set of fuzzing targets</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#sexiF0" aria-expanded="false" aria-controls="sexiF0">
<div class="h4"> <!-- 1 -->🐛 Bug Fixes <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="sexiF0">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/c81d484294d532f4bfebdefe1a22693d8ce6b4bc">c81d484</a> Tests failing on mac</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/9bbf9433e6c31a3fdb16f997fbbde2069cee6489">9bbf943</a> Be polite and kill child processes in api integration tests</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/c1704b1464d776bea055982edff575c7f1411786">c1704b1</a> Wrong response size set</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/0fe2d9825bfef1a4a8daaf84315a667cd281a358">0fe2d98</a> Remove ineffectual broker integration test</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/ab805dae75bf06bb7f9f6926e6adaed5e1c29495">ab805da</a> Libc & rustix are making problems in CI for unknown reasons</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/258efe408cba74745dabe41a730e04b5a06b0b2d">258efe4</a> PSK broker integration did not work</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/8808ed5dbc380f5db23dc821973fd90f61c2e893">8808ed5</a> Quiet log level should be warn</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1ab457ed37bae69c64370f84a74c37704d96fc48">1ab457e</a> Print stack trace to errors propagated to main function</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/c9c266fe7ce63f0272a8e84869cf7d33c24630a2">c9c266f</a> Flush stdout after printing key update notification</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/37f7b3e4e924dde478cbfa6f927d44922d8699a9">37f7b3e</a> Consistently use feature flag `experiment_libcrux`</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/40377dce1f9eac4f78f6176bd1b9f62a667b4299">40377dc</a> Fix shared_secret length in Kyber encaps fuzz test</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/07146d9914da562782a9339f35e7f68f12d10517">07146d9</a> Update handle_msg.rs fuzz test and handshake.rs bench to use PublicBox</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/0e059af5dac819292d37dfd046a9f95270b63fb8">0e059af</a> Fix duplicate key issue (#329)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/0e8945db7894d4bb94be0ce5cd70487c7d23bd61">0e8945d</a> .ci/gen-workflow-files.nu script</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/cd23e9a2d07b791cccb51e85d3c8c4e5bd49a405">cd23e9a</a> Failing tests</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/13a853ff429e431c1a4efbe688582e493247e42a">13a853f</a> Fix crate vulnerabilities</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/639541ab4ffea0c2fea5c6163c239bb872312e99">639541a</a> Grammatical typo in cli.rs</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/62aa9b4351536a0bd0eeaae14878e0c3b691b3c2">62aa9b4</a> Second round of clippy lints</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/26cb4a587f243c5c8e32bb9da70c09d2a8088e0a">26cb4a5</a> Apply clippy lints</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1c14be38ddd71cde9dcfcd9b52ba7cee060d6b58">1c14be3</a> Make benches work again</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/9824db4f0917a3a88b4e1c742a5b09a7dd0116e0">9824db4</a> Migrate away from lazy_static in favor of thread_local</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e3b72487db6f9299dee1d4e0b11e77658fd867b1">e3b7248</a> Make sure all tests are run during CI runs</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7c83e244f988646a96c764b09f16ed3f4e53f32d">7c83e24</a> Fix Rust code in markdown files</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/61ef5b92bbe15f50d1eb344e23cc9795cb666af5">61ef5b9</a> Add deprecated keygen command</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/9819148b6f7473b60ccff3e338299cfb1e0b135c">9819148</a> Remove OSFONTDIR var from whitepaper build</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1eefb5f2631eaf1cffd616a0e527502aef614003">1eefb5f</a> Guaranteed results typo</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/284ebb261f1b0c14e0dd120fba4e032a9e787eef">284ebb2</a> Enabled fuzzing</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/40861cc2ea8922894c712989527aeeb59a29e6e7">40861cc</a> Nix flake failing due to rosenpass-to</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/46156fcb291740ddc0e21d9413299684a68b8301">46156fc</a> Setup cargo fmt to check the entire workspace</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#rotca0" aria-expanded="false" aria-controls="rotca0">
<div class="h4"> <!-- 2 -->🚜 Refactor <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="rotca0">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/81487b103d3dad97506f37cc168604343fd5cd89">81487b1</a> Get rid of comment and unessary truncation of buffer</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/8ea253f86bef8f974becc90042a5d58231407de5">8ea253f</a> Use memoffset crate instead of unstable offset_of feature</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a996b082796308a4ee7c2124621156a32989aa0a">a996b08</a> Replace lenses library with the zerocopy crate</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#noita0" aria-expanded="false" aria-controls="noita0">
<div class="h4"> <!-- 3 -->📚 Documentation <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="noita0">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/3cd607774a378215a735bb7da63d8ad8b91f4e31">3cd6077</a> Added gitcliff and modified template</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1f7196e4733a1364033b44c1f4b84c84c1cc4aab">1f7196e</a> Add documentation for testing</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/de60e5f8f0d0190a5bd7fd1e11bcee35f6187677">de60e5f</a> Run prettier over CONTRIBUTING.md</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/b50ddda15110b91e1cc9cd32969ec7603464df85">b50ddda</a> Pointed to website documentation in readme</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7282fba3b3a03c23c8db9fd49948cff067e966e6">7282fba</a> Migrated cooking recipe from wiki</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/29917fd7a6c2d788cff7411f92724efd328f990b">29917fd</a> Fix keygen/gen-keys misspell</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/c9cef05b2967412012866f81ec7201a4dfa71883">c9cef05</a> Add bibliography to the manual page</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#gnily0" aria-expanded="false" aria-controls="gnily0">
<div class="h4"> <!-- 5 -->🎨 Styling <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="gnily0">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/fd8f2e4424b20b78e523ad0af5b0cedb825345be">fd8f2e4</a> Apply rustfmt</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#gnits0" aria-expanded="false" aria-controls="gnits0">
<div class="h4"> <!-- 6 -->🧪 Testing <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="gnits0">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/d913e19883343af54cd4a46109ce7de3e2f08a54">d913e19</a> Add tests for controlflow</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/9f78531979b2e59c1db48aa1835be5e7d417800e">9f78531</a> Cleanup fd.rs tests</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/849657176595b0ec8093db598c82d5931588c127">8496571</a> Modify existing tests to cover load/store for PublicBox as well</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#sksaT0" aria-expanded="false" aria-controls="sksaT0">
<div class="h4"> <!-- 9 -->📦 Miscellaneous Tasks <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="sksaT0">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e809e226dab2fd059343afcf722c482bd8d9b70a">e809e22</a> Fixed typo on doc-upload</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/4c20efc8a8bc2f703d737de861b0d1194ae6a4a8">4c20efc</a> Fix(API): Tests failing on mac</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/22389196571dd8fda7c1787b8a9fd6516afef9b1">2238919</a> Fd/time: add tests, docs, cleanups</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/624d8d2f44d6ccb8519d778fc7a10bd80ed1ed1b">624d8d2</a> API: Close connections after errors & use mio::Token based polling</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a831e01a5cd83c2ee3cf257821d86c3272649b64">a831e01</a> Utilities to check for unix domain stream sockets</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/3caff91515c6bddc42e1f386ec405428ae1cdd74">3caff91</a> Fallback for empty api section in config</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7a31b572273bf4202ea89986569ee8df073dccc9">7a31b57</a> Infrastructure to use endpoints with fd. passing</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/d5a8c85abe430f8685bd752a2e04286741c7fb8f">d5a8c85</a> Specifying a keypair should be opt. at startup</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/48f7ff93e3682736f7a85719c3e1027202b27e31">48f7ff9</a> Deal with CryptoServer being uninit.</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/5f6c36e7730c61871c9c9ebb6eb1b50e2b65c970">5f6c36e</a> Decouple AppServer from CryptoServer::timebase</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7b3b7612cf85c5e47d9885b9ccaf2c0d1b5dbb98">7b3b761</a> API should have access to AppServer</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/15002a74cc83682d121849a5f563dcae49bedec7">15002a7</a> Experimental PSK Broker Support</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/08653c3338ce265d54deec510fad1c847c01e017">08653c3</a> Clippy</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/520c8c6eaa908b5c7f0695fc206ce3a6fe426706">520c8c6</a> Feature naming scheme fully applied</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/fd0f35b2799faa03585fca717dd00ee8c898ec18">fd0f35b</a> Gen-key subcommand should show canonical paths</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/6fc45cab5352482e2b447b38788c8ac8314098d3">6fc45ca</a> Prettier</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/c359b87d0cabdc9007a4305a3905f8484b336b1a">c359b87</a> Convert broker interface setup to use mio's UnixStream where possible</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/355b48169bf841b661390ffd5b58f0434e57b88f">355b481</a> Make MiobrokerClient import conditional</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/274d245bedb8f7d200144b940fa4e812de78f2f9">274d245</a> Unify enable_wg_broker and enable_broker_api features</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7b6a9eebc19ac343d9a88abc8ff8ec42b5bdf574">7b6a9ee</a> Test full workspace with codecov</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/4554dc4bb38d67499474adfb2c731f5fb30a7976">4554dc4</a> Drop codecov token</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/465c6beaabbd7b556bf83c02c2135e9752d6dfdc">465c6be</a> Switch to codecov action v4 branch</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/9fd3df67eda3b3fbff5a710fa3bf0b5c143869cb">9fd3df6</a> Fix typos and add various comments</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/138e6b65533d90cad3255999ecedf0b93d701f09">138e6b6</a> To crate documentation indendation (purely cosmetic)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/2dde0a2b4710cad6c13aa68df85cfa1cb81c2a79">2dde0a2</a> Refactor integration_tests (purely cosmetic)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/3cc3b6009f9cb973a90ecdf34747e051ea1a2d3f">3cc3b60</a> Move CliCommand::run -> CliArgs::run; do not mutate the configuration</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/8d3c8790fe3ee15079c3af563cc919408629ff25">8d3c879</a> Reorganize memfd secret policy</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/648a94ead845aa3429a2917d1c89b57747083a21">648a94e</a> Clippy fixes on wireguard-broker</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/54ac5eecdbc55c589636fd878ac30417cdb7793c">54ac5ee</a> Warnings & clippy hints</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/40c5bbd167b86ec9a3b58368b4f18f7a1705c40f">40c5bbd</a> Ensure that rustAnalyzer is installed in dev environment</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a4b8fc222637509fc39ad25a35b9d229e45a6874">a4b8fc2</a> Move memcmp test API doc to test memcmp test module</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/deafc1c1af63fe7390ed6d3407cb4dca304fe6ef">deafc1c</a> Style adjustments – Cargo.toml</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/6bbe85a57b2257b5411f32d737f1341bc8b42a2e">6bbe85a</a> Remove unnecessary imports</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e70c5b33a84d8e56beef35449e4f31621503f76e">e70c5b3</a> Ignore vscode directory</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/f6320c3c355212f423d47ef90375226081709ef1">f6320c3</a> Fixup regression test</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/cc5877dd83dbe47213b7950eacf77058caac9e3d">cc5877d</a> Use my new name</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/cc22165dc4900c51a14448e1d6975ebda7345441">cc22165</a> Ensure punctuation is consistent in doc comments</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/100d7b6e1cb617aff66ca2a0ab7e301764bde9d3">100d7b6</a> Simplify some dereferencing incantations in PublicBox</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7c54a37618dbdfe639f19401809d4bd594d1d64e">7c54a37</a> Add generate_configs.py script</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/5f8b00d045a56002675d9c12b8e5f96a822fbdec">5f8b00d</a> Rollback symbolic models to original state</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/70c5ec2c299a5f542357be175f09b9a072ecb89c">70c5ec2</a> Remove libsodium references in nix flake, ci (#334)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/06969c406d6b3714f76886424aa5e89ad8b6637e">06969c4</a> Add write permissions in dependent-issues workflow</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a8ed0e8c6613bb2fbbc60b251e682a617d085323">a8ed0e8</a> Update codecov configuration file</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/ad6405f8652b1889a7475770154f37f096660246">ad6405f</a> Add codecov configuration file</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/761d5730af500be46f4e88c0a801ac5a1d12ad99">761d573</a> Changes from #160- Invoke the mandoc linter (#296)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/21e693a9da49fb4533cbc96edf39bc6c798b06ae">21e693a</a> Add codecov (llvm-cov) coverage (#297)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/be91b3049c5627357c01b3c7831760dd0b606ac9">be91b30</a> Load WireGuard SK into secret memory (#293)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/3e734e0d57fc4169828ce6283a9bbab13ca21696">3e734e0</a> Replace Into<> with From<> trait</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/c9e296794bb46cb3222760055b5a2fc87002d1e8">c9e2967</a> Remove useless conversion</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/bc6bff499d4a8e7e118ad03ab781e436937bc4dd">bc6bff4</a> Remove redundant Ok()</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/de905056fc52e9523265a56c935b0692da118376">de90505</a> Remove needless borrow</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/4e8344660ea2c287495f66b08c2d3470aed3deba">4e83446</a> Remove needless borrow</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a581f7dfa7e9ae8a7184ce7f9ca68079b0edc151">a581f7d</a> Replace if let with is_ok() call</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/bd6a6e5dce50059878220d31a257377a29dfb5eb">bd6a6e5</a> Remove needless borrow for nonce array</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e0496c12c64499b84b51e42a476ba5f4cb4ec742">e0496c1</a> Use copy instead of clone trait</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/f4116f2c20dac8cfaa64c2b51ff0950913dcae24">f4116f2</a> Remove redundant mutability</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/8099bc4bdd597303479820d9349ebc6926feff28">8099bc4</a> Remove redundant cast</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/39d174c605e8f039c6ad0a7ffda9be86cb439a63">39d174c</a> Suppress clippy warnings for neutral element</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/76d5093a201c594dd8870954c2f971c3e8961102">76d5093</a> Apply .ci/gen-workflow-files.nu script</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/ffd81b6a7294daf89c766609d8d5e54eee8e4cf8">ffd81b6</a> Update flake.lock</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/d1d218ac0fcb462535207ad855b338c3ad0e5df2">d1d218a</a> Add dedicated nixpkgs input to flake</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/199ecb814b3b11f41cfde79801fc77b1199f95dc">199ecb8</a> Add configuration</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/baa35af558fd9f8c8886e3abcc24b3bb17aac6f7">baa35af</a> Exclude rosenpass-fuzzing</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/b2de384fcf004d1889cfcd3c7b3920afc7068ea7">b2de384</a> Add secure memcmp_le function</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/c69fd889fb515f676f39ecb71ebe13854d980b0a">c69fd88</a> Enable cargo bench again</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/4d482aaab7f4e85db19b51c9860959d91458c4b8">4d482aa</a> Cargo fmt & fix</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/13df700ef57ac5a9ca166dfdf8cc54518afb5f50">13df700</a> Drop overlay due to upstream fix</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/4f4e8e101813fb504cff800a6c33697859384b60">4f4e8e1</a> Drop deprecated std::env::home_dir()</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/478fadb80d993fd256852df19b72825e03a7c211">478fadb</a> Enable aarch64-linux builds again</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7c1ada4b10b0e2becf160aae3b6f620fd4153671">7c1ada4</a> Add link to manual</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/96900851566236160cbe6a1c3ce889359fc1818f">9690085</a> Cargo fmt</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e42f90b0488fdddbcf8334daeebdbfa51b6176d8">e42f90b</a> Add helper to turn typenums into const values</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/30cb0e98018d0febb7921ecd58e197f0ada96004">30cb0e9</a> Remove references to libsodium from secret-memory</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/972e82b35f1765e488696e9caf441771d2ef9956">972e82b</a> Move kems out of rosenpass crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/838f700a74d5adf985651dfd4bd2251ffaff65a9">838f700</a> Upgrade dependencies</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/0f89ab7976c32568d11a4d2780bd9d2f50b5ea0c">0f89ab7</a> Shorten fuzzing runtime to make sure the CI finishes quickly</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/cf132bca1154b434a3340c7c69c73eb9834dd993">cf132bc</a> Move rest of coloring.rs into secret-memory crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7bda010a9b0126c980488a12a02a077a0d89f71c">7bda010</a> Move Public and debug_crypto_array into secret-memory crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/cc8c13e12182712012982cf01f6e9efa0e3934cd">cc8c13e</a> Remove lprf.rs (dead code)</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/09aa0e027ed5b0b3f95e62253dd6acd0b9de9f2e">09aa0e0</a> Move hashing functions into sodium/ciphers crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/86300ca9367adf9863e8af098dd0b8a4548e4b37">86300ca</a> Use naming scheme without rosenpass- for crates</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/3ddf736b60eee06ab0554dcd37a6a0453b4ac323">3ddf736</a> Move xchacha20 implementation out of rosenpass::sodium</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/c64e721c2fcca9cee41755f5dce00f85e302af21">c64e721</a> Move chacha20 implementation out of rosenpass::sodium</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/4c51ead078055b81c4696403b885e27efcd07d5f">4c51ead</a> Move libsodium's helper function into their own namespace</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/c5c34523f31c149d82073cd845fcb3f71e4de434">c5c3452</a> Move libsodium's memzero, randombytes fns into rosenpass-sodium</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/655314163702e416fa6c8ab347ac6b4abc41a918">6553141</a> Move libsodium's increment into rosenpass-sodium crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a3de526db8953fa1ba9a531de808cb4aed5442ee">a3de526</a> Move libsodium's compare into rosenpass-sodium crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/5da0e4115e01403a337e4edb547a6a65518c0ac0">5da0e41</a> Move memcmp into rosenpass-sodium crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/99634d9702497d3f64f42d1c18c5f034f6aa6a5a">99634d9</a> Move sodium init integration into rosenpass-sodium crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e50542193fadeade5a0f075c1345c796f6f4a29f">e505421</a> Move file utils into coloring or the util crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/3db9755580e00eb5ca50ddd19aec779e5e9f3091">3db9755</a> Move functional utils into utils library</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/556dbd26007cdfcea7eb1e932265621892066fb3">556dbd2</a> Move time utils into util crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/6cd42ebf5082ff025d4de0f155488d01ce966518">6cd42eb</a> Move max_usize into util crate</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a220c11e67d93e4045798e5e571f44186a1dec37">a220c11</a> Move xor_into, copying and base64 utils into own crates</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.2.1 <span class="">2023-11-18<span> - <a href="0b4b1279cf7f322a41387878dd7ceee1ed094e29" class="">0b4b127</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1700345782" aria-expanded="false" aria-controls="esael1700345782">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1700345782">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/0b4b1279cf7f322a41387878dd7ceee1ed094e29">0b4b127</a> Release rosenpass version 0.2.1</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.2.1-rc.3 <span class="">2023-11-18<span> - <a href="44264a7bb67895270bca88f2a450e2c95e3b4917" class="">44264a7</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1700344737" aria-expanded="false" aria-controls="esael1700344737">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1700344737">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/44264a7bb67895270bca88f2a450e2c95e3b4917">44264a7</a> Release rosenpass version 0.2.1-rc.3</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• rosenpass-v0.2.1-rc.2 <span class="">2023-11-18<span> - <a href="9597e485bfe2d74940b694a7bd012ae1adf1fe09" class="">9597e48</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1700344115" aria-expanded="false" aria-controls="esael1700344115">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1700344115">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/9597e485bfe2d74940b694a7bd012ae1adf1fe09">9597e48</a> Release rosenpass version 0.2.1-rc.2</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• rosenpass-v0.2.1-rc.1 <span class="">2023-11-18<span> - <a href="3901e668cba86195a2853dbae21c27c01780ddac" class="">3901e66</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1700343046" aria-expanded="false" aria-controls="esael1700343046">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1700343046">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/3901e668cba86195a2853dbae21c27c01780ddac">3901e66</a> Release rosenpass version 0.2.1-rc.1</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#sexiF1700343046" aria-expanded="false" aria-controls="sexiF1700343046">
<div class="h4"> <!-- 1 -->🐛 Bug Fixes <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="sexiF1700343046">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/27746781c0989ec3b6f7e501bfc0ac13ece2bdbf">2774678</a> Doctest should pass buffers of correct length to handle_msg</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/447a4f7a445786ee38c9be42d124b48d3abb5374">447a4f7</a> Restore benchmarks to working order</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#rotca1700343046" aria-expanded="false" aria-controls="rotca1700343046">
<div class="h4"> <!-- 2 -->🚜 Refactor <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="rotca1700343046">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/f48a923dbffbd3d0c80773cbd0eaf2845ab9f72e">f48a923</a> Remove redundant references</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#noita1700343046" aria-expanded="false" aria-controls="noita1700343046">
<div class="h4"> <!-- 3 -->📚 Documentation <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="noita1700343046">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/0051cbd48e34833694e5383af3c5c7470eba7798">0051cbd</a> Add unit test for xor_into</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1e37f89e83413ce28725006fd0fcd5aa3c4a54ef">1e37f89</a> Clarify the assumptions about the server</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#gnits1700343046" aria-expanded="false" aria-controls="gnits1700343046">
<div class="h4"> <!-- 6 -->🧪 Testing <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="gnits1700343046">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/f32383996723d5723ae38bb1f4c66afda6a9d415">f323839</a> Fix wrong comment</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/b7a76849b7dee49cadf8aa182e88b4a94fe5f788">b7a7684</a> Ensure 8MiB of stack size for key generation</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#sksaT1700343046" aria-expanded="false" aria-controls="sksaT1700343046">
<div class="h4"> <!-- 9 -->📦 Miscellaneous Tasks <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="sksaT1700343046">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/932bde39cca21ea0c9348d026d7431ca1a48e64d">932bde3</a> Update</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/13563237cbc90075844556bfb582e4591b8d7249">1356323</a> Rustfmt</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e5e04c6d95a321bf1ae00dbdb59472ad972263ea">e5e04c6</a> Replace `is_ok()` by `if let`</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/6e15c38254a922604788cbffce362d0ce65f3d53">6e15c38</a> Remove redundant stack increase</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/04eb86af870078282969a59ab97cfa5596fc8a7f">04eb86a</a> Move wg exit status check to thread</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/bf850e3072297be6e47f406ad573ec09beb210c7">bf850e3</a> Handle the exit status of wg process</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/dd3993622003f87d5a279fcd5f947c977ace25d5">dd39936</a> Reap spawned wireguard child</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/b50820ecc03f370b2ae68b71b205fb3d650f283f">b50820e</a> Default `WireGuard::extra_params` to empty `Vec`</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1135cd7bbb0ea663ade15eda1e7589d594783d44">1135cd7</a> Remove `unsafe` from `store_secret`</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/51f04f749fada960ab8871a0f22ed323707d9de1">51f04f7</a> Remove `unsafe` from `store_secret`</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/d0a84294aa904d4461bf7f0cba9eecb96dcc0912">d0a8429</a> Move `StaticKEM::keygen` out of `unsafe`</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/d6a7ebe88faf46afbc7e20fa56a755d3e4977b53">d6a7ebe</a> Allow false positive with redundancies</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/212336728c0735bec733f0babfc0ba717c809ab6">2123367</a> Fix clippy warnings in `build.rs`</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.2.0 <span class="">2023-09-05<span> - <a href="b997238f428a0fd2276da8014e9e8c7ee66d711c" class="">b997238</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1693935230" aria-expanded="false" aria-controls="esael1693935230">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1693935230">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/b997238f428a0fd2276da8014e9e8c7ee66d711c">b997238</a> Release rosenpass version 0.2.0</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.2.0-rc.1 <span class="">2023-08-29<span> - <a href="d915e63445ac384740d60ae41821fa5a3831636a" class="">d915e63</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#serut1693345728" aria-expanded="false" aria-controls="serut1693345728">
<div class="h4"> <!-- 0 -->🚀 Features <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="serut1693345728">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/62fab066d4f544cc304ec46855b6a72ca38d303c">62fab06</a> Restart host discovery on connection loss</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/b4d74d64f7c751ade233aa15cb4a6b8eaa4eb586">b4d74d6</a> Upload man pages to website</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#sexiF1693345728" aria-expanded="false" aria-controls="sexiF1693345728">
<div class="h4"> <!-- 1 -->🐛 Bug Fixes <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="sexiF1693345728">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7e6985fdc6a76eac65d129682d94ecc18160ab17">7e6985f</a> Revert spell correction zeroized -> zeroed</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/b958eacaaec5e8dfe7c1f62c62bf6ce6bb5fd32a">b958eac</a> Typos in Rust code, readme and man pages</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/397a776c55b1feae1e8e5aceef01cf06bf56b6ed">397a776</a> Race condition due to concurrent handshake</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/19fe7360d2b220d8116aa9be41c3b2f330c215e5">19fe736</a> Git directory detection should not print an error if we are not in a git repo</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/b29720b0c67ddf96f114c134bed076f27018313e">b29720b</a> Formatting</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/78e32a6f1401ccb83dfbd4bb958cc70f9d22676d">78e32a6</a> Show cargo fmt errors</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/5f78857ff586713889ba638c279964b67d407100">5f78857</a> Show warnings from git directory detection</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/69f62673a59a30b09854bd2d208bace33e9b6980">69f6267</a> Reintroduce ability to actually supply wireguard with keys</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7aa48b95af555ace33d05dcf09d89561e2690172">7aa48b9</a> Escape uses of angle brackets and pointy brackets in documentation</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/229224d078fba94ff3f3f6f22f7610c7bada10d9">229224d</a> Restore QC/doc CI job to operation</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e12cd18a42caef668857dcc2d5f5b74d70223afa">e12cd18</a> Disable broken CI jobs</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/9469b62f589cd6f43bb956a8a2baa96e2c7e04a1">9469b62</a> Host-path discovery</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/f8bea94330cfa5c61c7b02cbbb45d6826c380730">f8bea94</a> Always send messages to a peer using the socket they contacted us with</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/f3c343c472ed95c829c2b84a5ded1cb32efbe388">f3c343c</a> Handle the various possible dual-stack configurations reliably</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/42798699e4ff9897f71f10316f9e935d9a9fddb6">4279869</a> Adjust the rp(1) script to support the new rosenpass(1) command line parameters</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#noita1693345728" aria-expanded="false" aria-controls="noita1693345728">
<div class="h4"> <!-- 3 -->📚 Documentation <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="noita1693345728">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/0456ded6b970f0dec449e5b39fdc16beb38ac86d">0456ded</a> Add a manual page for `rp(1)`</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#sksaT1693345728" aria-expanded="false" aria-controls="sksaT1693345728">
<div class="h4"> <!-- 9 -->📦 Miscellaneous Tasks <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="sksaT1693345728">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/6025623aadadf70d676c95c402a8eba5f866930e">6025623</a> Update outdated dependencies</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/5a67b4708afb5a6a75645c1112ba612bbd31eb1c">5a67b47</a> Perform a `shellcheck`</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/66e696fea388503b392d1be5fe81cd502a91fe1b">66e696f</a> Update</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/8ff9b53365fc855d6b2294eeb815ab456cbfe84e">8ff9b53</a> Include a static compiled manual page</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/067a839d4b7899b887916becb2aae001de530c16">067a839</a> Defaults to dual-stack</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/38835fb0f8a4954f7656c8865897df1d408072a8">38835fb</a> Add mirrors</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/0d2ca37bbbcfb3173dbf839c2ab033aa210d121e">0d2ca37</a> Update</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/097fd0332d5636d17bb7142e33989cad7f1ef2d3">097fd03</a> Upgrade crate dependencies</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/3856d774ff6c6954a3157d322d9846637d635c6a">3856d77</a> Move slides into their own repo</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/7154af52f9eede2bf57e8a3cb5f835b9f7958145">7154af5</a> Indicate that the listen parameter can be given multiple times in the help</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e03fed404f570fabdaa6f290e52e7c7a6777aebc">e03fed4</a> Cleanup unneccesary debug output</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.1.2-rc.4 <span class="">2023-04-13<span> - <a href="94d57f2f87a41c8ae902cbdf0273541a90419a54" class="">94d57f2</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1681408329" aria-expanded="false" aria-controls="esael1681408329">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1681408329">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/94d57f2f87a41c8ae902cbdf0273541a90419a54">94d57f2</a> Release rosenpass version 0.1.2-rc.4</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#serut1681408329" aria-expanded="false" aria-controls="serut1681408329">
<div class="h4"> <!-- 0 -->🚀 Features <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="serut1681408329">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/25a7a0736ba1c401f9c42a5a3c688344a3a2fad5">25a7a07</a> Reorder RWPQC slides</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a723951c71e1e02c67ba11614882ae96e3ab7501">a723951</a> CrossFyre 2023 Submission abstract</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/34d0bab5c56e4f38bd9085f0ff51542cd47481f3">34d0bab</a> Add RWPQC 23 slides</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/2aeb9067e25720a2a573449dcbda5ec15fb958a9">2aeb906</a> Add YRCS talk slides</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/5afa6c19a6d5bb4fd2239048eab22ce3daccf009">5afa6c1</a> Add licensing infos</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#sexiF1681408329" aria-expanded="false" aria-controls="sexiF1681408329">
<div class="h4"> <!-- 1 -->🐛 Bug Fixes <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="sexiF1681408329">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a011cc1e1c08ca3bf824b77d7d8af439487dbada">a011cc1</a> Rollback adding an article to state, acknowledgement and replay</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/8eea5284bfeae2d96e75e93f1d90a90940af9747">8eea528</a> Remove warning about this being a research project</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#noita1681408329" aria-expanded="false" aria-controls="noita1681408329">
<div class="h4"> <!-- 3 -->📚 Documentation <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="noita1681408329">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/279b3c49fc134b3adc558bdfa4dda560ee25dc52">279b3c4</a> Add rosenpass.1 manual page</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#sksaT1681408329" aria-expanded="false" aria-controls="sksaT1681408329">
<div class="h4"> <!-- 9 -->📦 Miscellaneous Tasks <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="sksaT1681408329">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/a62405190e559792330b381f2cfc01869ff5ccea">a624051</a> Consistently use the term `Key Encapsulation Mechanism`</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/ecc1b75b00304b257e52d7581772127f3b7360ce">ecc1b75</a> Delete outdated illustrations</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.1.1 <span class="">2023-02-25<span> - <a href="97f5d75838d4dd73f1ed507b8f236b34a48ab773" class="">97f5d75</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1677364480" aria-expanded="false" aria-controls="esael1677364480">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1677364480">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/97f5d75838d4dd73f1ed507b8f236b34a48ab773">97f5d75</a> Release rosenpass version 0.1.1</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.1.1-rc.7 <span class="">2023-02-25<span> - <a href="aa15872f2b693cac416225bc7abcd1c989f4431a" class="">aa15872</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1677363695" aria-expanded="false" aria-controls="esael1677363695">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1677363695">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/aa15872f2b693cac416225bc7abcd1c989f4431a">aa15872</a> Release rosenpass version 0.1.1-rc.7</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/1d10e7f0369605665482e092a9b3c56a2c9f2cf3">1d10e7f</a> Release rosenpass version 0.1.1-rc.6</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.1.1-rc.5 <span class="">2023-02-25<span> - <a href="f4c351c74bf4c82a60894b1c8ccb90d80fc17ecb" class="">f4c351c</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1677351218" aria-expanded="false" aria-controls="esael1677351218">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1677351218">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/f4c351c74bf4c82a60894b1c8ccb90d80fc17ecb">f4c351c</a> Release rosenpass version 0.1.1-rc.5</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.1.1-rc.4 <span class="">2023-02-25<span> - <a href="4b4902cacdd445a0673eb9d7273546df6d1b921d" class="">4b4902c</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1677329250" aria-expanded="false" aria-controls="esael1677329250">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1677329250">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/4b4902cacdd445a0673eb9d7273546df6d1b921d">4b4902c</a> Release rosenpass version 0.1.1-rc.4</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/9b3f4670afaaf55e08d5ee173e868c76cb10f518">9b3f467</a> Release rosenpass version 0.1.1-rc.3</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.1.1-rc.3 <span class="">2023-02-24<span> - <a href="8313a61cc7eed015176722e2fd06ea44eac432bd" class="">8313a61</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1677267423" aria-expanded="false" aria-controls="esael1677267423">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1677267423">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/8313a61cc7eed015176722e2fd06ea44eac432bd">8313a61</a> Release rosenpass version 0.1.1-rc.3</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.1.1-rc.2 <span class="">2023-02-24<span> - <a href="d50c3fc33abab060b0eed04c0d0299ad7fa5accd" class="">d50c3fc</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1677253325" aria-expanded="false" aria-controls="esael1677253325">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1677253325">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/d50c3fc33abab060b0eed04c0d0299ad7fa5accd">d50c3fc</a> Release rosenpass version 0.1.1-rc.2</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#serut1677253325" aria-expanded="false" aria-controls="serut1677253325">
<div class="h4"> <!-- 0 -->🚀 Features <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="serut1677253325">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/aaf79beef344fcdbfa4354f5da61d43ae225e2c7">aaf79be</a> Give thanks to NLNet</div>

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/22c238764a87c6d2231d22e529575380dd044788">22c2387</a> `rp` now detects rosenpass binary in nix builds</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#sexiF1677253325" aria-expanded="false" aria-controls="sexiF1677253325">
<div class="h4"> <!-- 1 -->🐛 Bug Fixes <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="sexiF1677253325">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/55e4fc7e9aace57874503d4b6a0c879504123479">55e4fc7</a> Support for absolute paths in rp</div>
</div>
</div>


</div><div class="changelog-container card card-body">
<div class="h3 changelog-release">• 0.1.1-rc.1 <span class="">2023-02-24<span> - <a href="e34610ac8b75b86f00a737f2a10cd516671d8d15" class="">e34610a</a></div>
<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#esael1677234622" aria-expanded="false" aria-controls="esael1677234622">
<div class="h4"> <!-- 0 -->📝 Release <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="esael1677234622">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/e34610ac8b75b86f00a737f2a10cd516671d8d15">e34610a</a> Release rosenpass version 0.1.1-rc.1</div>
</div>
</div>

<p>
<button class="btn btn-primary changelog" type="button" data-toggle="collapse" data-target="#sexiF1677234622" aria-expanded="false" aria-controls="sexiF1677234622">
<div class="h4"> <!-- 1 -->🐛 Bug Fixes <i class="fa-solid fa-sort-down"></i></div>
</button>
</p>
<div class="collapse changelog" id="sexiF1677234622">
<div class="card card-body">

<div class="changelog-commit"> - <a href="https://github.com/rosenpass/rosenpass/commit/83d5f379de41aedc15964fb4f8dceb88310b4ec0">83d5f37</a> Proofreading of whitepaper</div>
</div>
</div>


</div><!-- generated by git-cliff -->
