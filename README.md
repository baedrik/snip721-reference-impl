# Configurable SNIP-20 Token Contract
This is a modification of the base [SNIP-20 Reference Implementation](https://github.com/enigmampc/snip20-reference-impl) that allows you to configure your desired functionality when instantiating your token.  The configuration choices are:
* Public Total Supply:  If you enable this, the token's total supply will be displayed whenever a TokenInfo query is performed.  DEFAULT: false
* Enable Deposit: If you enable this, you will be able to convert from SCRT to the token.*  DEFAULT: false
* Enable Redeem: If you enable this, you will be able to redeem your token for SCRT.*  It should be noted that if you have redeem enabled, but deposit disabled, all redeem attempts will fail unless someone has sent SCRT to the token contract.  DEFAULT: false
* Enable Mint: If you enable this, any address in the list of minters will be able to mint new tokens.  The admin address is the default minter, but can use the set/add/remove_minters functions to change the list of approved minting addresses.  DEFAULT: false
* Enable Burn: If you enable this, addresses will be able to burn their tokens.  DEFAULT: false


\*:The conversion rate will be 1 uscrt for 1 minimum denomination of the token.  This means that if your token has 6 decimal places, it will convert 1:1 with SCRT.  If your token has 10 decimal places, it will have an exchange rate of 10000 SCRT for 1 token.  If your token has 3 decimal places, it will have an exchange rate of 1000 tokens for 1 SCRT.  You can use the exchange_rate query to view the exchange rate for the token.  The query response will display either how many tokens are worth 1 SCRT, or how many SCRT are worth 1 token.  That is, the response lists the symbol of the coin that is worth less, and the number of those coins that are worth 1 of the other.

I opted for this style of conversion so that there will never be any tokens lost due to a difference in the number of decimal places when exchanging to/from SCRT (i.e., if the exchange rate was fixed to 1:1 with SCRT, but your token had 18 decimal places, redeeming anything less than 0.000001 would burn your tokens but not give you any SCRT).  If people would prefer to have it fixed to 1:1 with SCRT and accept losing tokens/SCRT to differences in decimal places, I can make that change.  Personally I would probably just suggest that if you want your token pegged 1:1 to the value of SCRT, you might consider just giving it 6 decimal places to match.

## Differences from the Base SNIP-20 Reference Implementation
* Token symbol may contain digits
* Token may have more than 18 decimal places
* You can redeem tokens to an address other than yourself using the RedeemTo function:
```sh
secretcli tx compute execute --label *your_token_label* '{"redeem_to":{"recipient":"*address_to_receive_the_SCRT*","amount":"*amount_to_redeem_in_smallest_token_denomination*"}}' --from *your_alias_or_address* --gas 130000 -y
```
* To view the configuration of the token contract:
```sh
secretcli q compute query *token_contract_address* '{"token_config":{}}'
```

## Creating Your SNIP-20 Token
To create a new SNIP20 token:
```sh
secretcli tx compute instantiate *code_id* '{"name":"*your_token_name*","symbol":"*your_token_symbol*","admin":"*optional_admin_address_defaults_to_the_from_address*","decimals":*number_of_decimals*,"initial_balances":[{"address":"*address1*","amount":"*amount_for_address1*"}],"prng_seed":"*base64_encoded_string*","config":{"public_total_supply":*true_or_false*,"enable_deposit":*true_or_false*,"enable_redeem":*true_or_false*,"enable_mint":*true_or_false*,"enable_burn":*true_or_false*}}' --label *your_label* --from *your_alias_or_address* --gas 180000 -y
```
The `admin` field is optional and will default to the "--from" address if you do not specify it.  The `initial_balances` field is optional, and you can specify as many addresses/balances as you like.  The `config` field as well as every field in the `config` is optional.  Any `config` fields not specified will default to `false`.

## Words of Caution
The `token_config` query is your friend.  If you see that a token has deposit, redeem, and mint all enabled, be aware that the creator could have the ability to wait until people deposit SCRT for the token, and then mint a bunch of new tokens to redeem for all the SCRT that has been deposited.  If those are all enabled, you will want to be sure that there is some programmatic control over the minting of the token, i.e., minting is controlled by a contract that only mints when some reasonable event triggers it.  That is a good rule of thumb for minting in general.  It is better if a contract controls the minting rather than a person who can mint at will.  The `minters` query will list the addresses that have the ability to mint.