// flag: --dependency=tests/sources/functional/script_provider.move
// separate_baseline: no_opaque
script {
use 0x1::ScriptProvider;


fun main<Token: store>(account: signer) {
    ScriptProvider::register<Token>(&account);
}

spec main {
    pragma verify = true;
    aborts_if false;
}
}
