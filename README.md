# SNIP-721 Reference Implementation
This is a reference implementation of the [SNIP-721 specification](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-721.md) (which is currently being updated).  It not only implements the base requirements of SNIP-721,  but it also includes additional functionality that may be helpful for many use cases.  As SNIP-721 is a superset of the CW-721 specification, this implementation is CW-721 compliant; however, because CW-721 does not support privacy, a number of the CW-721-compliant functions may not return all the information a CW-721 implementation would.  For example, the OwnerOf query will not display the approvals for a token unless the token owner has supplied his address and viewing key.  In order to strive for CW-721 compliance, a number of functions that require authentication use optional parameters that the CW-721 counterpart does not have.  If the optional authentication parameters are not supplied, the responses will only display information that the token owner has made public.

### Terms
- __Message__ - This is an on-chain interface. It is triggered by sending a transaction, and receiving an on-chain response which is read by the client. Messages are authenticated both by the blockchain, and by the secret enclave.
- __Query__ - This is an off-chain interface. Queries are done by returning data that a node has locally, and are not public. Query responses are returned immediately, and do not have to wait for blocks.
- __Cosmos Message Sender__ - The account that is found under the `sender` field in a standard Cosmos SDK message. This is also the signer of the message.

### Padding
Users may want to enforce constant length messages to avoid leaking data. To support this functionality, every message includes an optional `padding` field. This optional `padding` field is ignored during message processing.

### Requests
Requests should be sent as base64 encoded JSON. Future versions of Secret Network may add support for other formats as well, but at this time we recommend usage of JSON only. For this reason the parameter descriptions specify the JSON type which must be used. In addition, request parameters will include in parentheses a CosmWasm (or other) underlying type that this value must conform to. E.g. a recipient address is sent as a string, but must also be parsed to a bech32 address.

### Responses
Message responses will be JSON encoded in the `data` field of the Cosmos response, rather than in the `logs`, except in the case of Mint and BatchMint messages, where the token ID(s) will be returned in both the `data` and `logs` fields.  This is because minting may frequently be done by a contract, and `data` fields of responses from callback messages do not get forwarded to the sender of the initial message.

# Instantiating The Token Contract
##### Request
```
{
    “name”: “name_of_the_token”,
    “symbol”: “token_symbol”,
	“admin”: “optional_admin_address”,
	“entropy”: “string_used_as_entropy_when_generating_random_viewing_keys”,
	“config”: {
		“public_token_supply”: true_or_false,
		“public_owner”: true_or_false,
		“enable_sealed_metadata”: true_or_false,
		“unwrapped_metadata_is_private”: true_or_false,
		“minter_may_update_metadata”: true_or_false,
		“owner_may_update_metadata”: true_or_false,
		“enable_burn”: true_or_false
		},
	“post_init_callback”: {
		“msg”: “base64_encoded_JSON_representing_the_msg_to_perform_after_initialization”,
		“contract_address”: “address_of_the_contract_being_called_after_initialization”,
		“code_hash”: “code_hash_of_the_contract_being_called_after_initialization”,
		“send”: [
			“denom”: “denom_string_for_native_coin_being_sent_with_this_message”,
			“amount”: “amount_of_native_coin_being_sent”
			],
		}
}
```
| Name               | Type              | Description                                                         | Optional | Value If Omitted   |
|--------------------|-------------------|---------------------------------------------------------------------|----------|--------------------|
| name               | string            | Name of the token contract                                          | no       |                    |
| symbol             | string            | Token contract symbol                                               | no       |                    |
| admin              | string (HumanAddr)| Address to be given admin authority                                 | yes      | env.message.sender |
| entropy            | string            | String used as entropy when generating random viewing keys          | no       |                    |
| config             | defined below     | Privacy configuration for the contract                              | yes      | defined below      |
| post_init_callback | defined below     | Information used to perform a callback message after initialization | yes      | None               |

#### Config (Optional)
| Name                          | Type | Optional | Value If Omitted |
|-------------------------------|------|----------|------------------|
| public_token_supply           | bool | yes      | false            |
| public_owner                  | bool | yes      | false            |
| enable_sealed_metadata        | bool | yes      | false            |
| unwrapped_metadata_is_private | bool | yes      | false            |
| minter_may_update_metadata    | bool | yes      | true             |
| owner_may_update_metadata     | bool | yes      | false            |
| enable_burn                   | bool | yes      | false            |

This is the privacy configuration for the contract.
* public_token_supply - This config value indicates whether the token IDs and the number of tokens controlled by the contract are public.  If the token supply is private, only minters can view the token IDs and number of tokens controlled by the contract (default: False)
* public_owner - This config value indicates whether token ownership is public or private by default.  Regardless of this setting a user has the ability to change whether the ownership of their tokens is public or private (default: False)
* enable_sealed_metadata - This config value indicates whether sealed metadata should be enabled.  If sealed metadata is enabled, the private metadata of a newly minted token is not viewable by anyone, not even the owner, until the owner calls the Reveal function.  When Reveal is called, the sealed metadata is irreversibly unwrapped and moved to the public metadata (as default).  If unwrapped_metadata_is_private is set to true, the sealed metadata will remain as private metadata after unwrapping, but the owner will now be able to see it.  Anyone will be able to query the token to know whether it has been unwrapped.  This simulates buying/selling a wrapped card that no one knows which card it is until it is unwrapped. If sealed metadata is not enabled, all tokens are considered unwrapped when minted (default: False)
* unwrapped_metadata_is_private - This config value indicates if the Reveal function should keep the sealed metadata private after unwrapping.  This config value is ignored if sealed metadata is not enabled (default: False)
* minter_may_update_metadata - This config value indicates whether a minter is permitted to update a token's metadata (default: True)
* owner_may_update_metadata - This config value indicates whether the owner of a token is permitted to update a token's metadata (default: False)
* enable_burn - This config value indicates whether burn functionality is enabled (default: False)

#### Post Init Callback (Optional)
| Name             | Type                       | Description                                                                                         | Optional | Value If Omitted |
|------------------|----------------------------|-----------------------------------------------------------------------------------------------------|----------|------------------|
| msg              | string (base64 encoded)    | Base64 encoded JSON representation of the callback message to perform after contract initialization | no       |                  |
| contract_address | string (HumanAddr)         | Address of the contract to call after initialization                                                | no       |                  |
| code_hash        | string                     | Code hash of the contract to call after initialization                                              | no       |                  |
| send             | array (of Coin, see below) | List of native Coin amounts to send with the callback message                                       | no       |                  |

This is the optional callback message to execute after the token contract has initialized.  This can be useful if another contract is instantiating this token contract and needs the token contract to inform the creating contract of the address it has been given

#### Coin
| Name   | Type             | Description                                                               | Optional | Value If Omitted |
|--------|------------------|---------------------------------------------------------------------------|----------|------------------|
| denom  | string           | The denomination of the native Coin (uscrt for SCRT)                      | no       |                  |
| amount | string (Uint128) | The amount of the native Coin to send with the Post Init Callback message | no       |                  |

This is the payment to send with the post-init callback message.  Although `send` is not an optional field of the Post Init Callback, because it is an array, you can just use `[]` to not send any payment with the callback message

# Messages