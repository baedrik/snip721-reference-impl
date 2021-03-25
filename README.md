# SNIP-721 Reference Implementation
This is a reference implementation of the [SNIP-721 specification](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-721.md) (which is currently being updated).  It not only implements the base requirements of SNIP-721,  but it also includes additional functionality that may be helpful for many use cases.  As SNIP-721 is a superset of the [CW-721 specification](https://github.com/CosmWasm/cosmwasm-plus/blob/master/packages/cw721/README.md), this implementation is CW-721 compliant; however, because CW-721 does not support privacy, a number of the CW-721-compliant functions may not return all the information a CW-721 implementation would.  For example, the OwnerOf query will not display the approvals for a token unless the token owner has supplied his address and viewing key.  In order to strive for CW-721 compliance, a number of functions that require authentication use optional parameters that the CW-721 counterpart does not have.  If the optional authentication parameters are not supplied, the responses will only display information that the token owner has made public.

### Terms
- __Message__ - This is an on-chain interface. It is triggered by sending a transaction, and receiving an on-chain response which is read by the client. Messages are authenticated both by the blockchain, and by the secret enclave.
- __Query__ - This is an off-chain interface. Queries are done by returning data that a node has locally, and are not public. Query responses are returned immediately, and do not have to wait for blocks.
- __Cosmos Message Sender__ - The account that is found under the `sender` field in a standard Cosmos SDK message. This is also the signer of the message.

### Padding
Users may want to enforce constant length messages to avoid leaking data. To support this functionality, every message includes an optional `padding` field. This optional `padding` field is ignored during message processing.

### Requests
Requests should be sent as base64 encoded JSON. Future versions of Secret Network may add support for other formats as well, but at this time we recommend usage of JSON only. For this reason the parameter descriptions specify the JSON type which must be used. In addition, request parameters will include in parentheses a CosmWasm (or other) underlying type that this value must conform to. E.g. a recipient address is sent as a string, but must also be parsed to a bech32 address.

### Responses
Message responses will be JSON encoded in the `data` field of the Cosmos response, rather than in the `logs`, except in the case of MintNft and BatchMintNft messages, where the token ID(s) will be returned in both the `data` and `logs` fields.  This is because minting may frequently be done by a contract, and `data` fields of responses from callback messages do not get forwarded to the sender of the initial message.

# Instantiating The Token Contract
##### Request
```
{
    “name”: “name_of_the_token”,
    “symbol”: “token_symbol”,
	“admin”: “optional_admin_address”,
	“entropy”: “string_used_as_entropy_when_generating_random_viewing_keys”,
	“config”: {
		“public_token_supply”: true|false,
		“public_owner”: true|false,
		“enable_sealed_metadata”: true|false,
		“unwrapped_metadata_is_private”: true|false,
		“minter_may_update_metadata”: true|false,
		“owner_may_update_metadata”: true|false,
		“enable_burn”: true|false
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
| post_init_callback | defined below     | Information used to perform a callback message after initialization | yes      | nothing            |

### Config (Optional)
Config is the privacy configuration for the contract.
* public_token_supply - This config value indicates whether the token IDs and the number of tokens controlled by the contract are public.  If the token supply is private, only minters can view the token IDs and number of tokens controlled by the contract (default: False)
* public_owner - This config value indicates whether token ownership is public or private by default.  Regardless of this setting a user has the ability to change whether the ownership of their tokens is public or private (default: False)
* enable_sealed_metadata - This config value indicates whether sealed metadata should be enabled.  If sealed metadata is enabled, the private metadata of a newly minted token is not viewable by anyone, not even the owner, until the owner calls the Reveal function.  When Reveal is called, the sealed metadata is irreversibly unwrapped and moved to the public metadata (as default).  If unwrapped_metadata_is_private is set to true, the sealed metadata will remain as private metadata after unwrapping, but the owner will now be able to see it.  Anyone will be able to query the token to know whether it has been unwrapped.  This simulates buying/selling a wrapped card that no one knows which card it is until it is unwrapped. If sealed metadata is not enabled, all tokens are considered unwrapped when minted (default: False)
* unwrapped_metadata_is_private - This config value indicates if the Reveal function should keep the sealed metadata private after unwrapping.  This config value is ignored if sealed metadata is not enabled (default: False)
* minter_may_update_metadata - This config value indicates whether a minter is permitted to update a token's metadata (default: True)
* owner_may_update_metadata - This config value indicates whether the owner of a token is permitted to update a token's metadata (default: False)
* enable_burn - This config value indicates whether burn functionality is enabled (default: False)

| Name                          | Type | Optional | Value If Omitted |
|-------------------------------|------|----------|------------------|
| public_token_supply           | bool | yes      | false            |
| public_owner                  | bool | yes      | false            |
| enable_sealed_metadata        | bool | yes      | false            |
| unwrapped_metadata_is_private | bool | yes      | false            |
| minter_may_update_metadata    | bool | yes      | true             |
| owner_may_update_metadata     | bool | yes      | false            |
| enable_burn                   | bool | yes      | false            |

### Post Init Callback (Optional)
Post)init_callback is the optional callback message to execute after the token contract has initialized.  This can be useful if another contract is instantiating this token contract and needs the token contract to inform the creating contract of the address it has been given

| Name             | Type                       | Description                                                                                         | Optional | Value If Omitted |
|------------------|----------------------------|-----------------------------------------------------------------------------------------------------|----------|------------------|
| msg              | string (base64 encoded)    | Base64 encoded JSON representation of the callback message to perform after contract initialization | no       |                  |
| contract_address | string (HumanAddr)         | Address of the contract to call after initialization                                                | no       |                  |
| code_hash        | string                     | Code hash of the contract to call after initialization                                              | no       |                  |
| send             | array (of Coin, see below) | List of native Coin amounts to send with the callback message                                       | no       |                  |

#### Coin
Coin is the payment to send with the post-init callback message.  Although `send` is not an optional field of the Post Init Callback, because it is an array, you can just use `[]` to not send any payment with the callback message

| Name   | Type             | Description                                                               | Optional | Value If Omitted |
|--------|------------------|---------------------------------------------------------------------------|----------|------------------|
| denom  | string           | The denomination of the native Coin (uscrt for SCRT)                      | no       |                  |
| amount | string (Uint128) | The amount of the native Coin to send with the Post Init Callback message | no       |                  |


# Messages
## MintNft
MintNft mints a single token.

##### Request
```
{
	"mint_nft": {
		"token_id": "optional_ID_of_new_token",
		"owner": "optional_address_the_new_token_will_be_minted_to",
		"public_metadata": {
			"name": "optional_public_name",
			"description": "optional_public_text_description",
			"image": "optional_public_uri_pointing_to_an_image_or_additional_off-chain_metadata"
		},
		"private_metadata": {
			"name": "optional_private_name",
			"description": "optional_private_text_description",
			"image": "optional_private_uri_pointing_to_an_image_or_additional_off-chain_metadata"
		},
		"memo": "optional_memo_for_the_mint_tx",
		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name             | Type                       | Description                                                                                            | Optional | Value If Omitted     |
|------------------|----------------------------|--------------------------------------------------------------------------------------------------------|----------|----------------------|
| token_id         | string                     | Identifier for the token to be minted                                                                  | yes      | minting order number |
| owner            | string (HumanAddr)         | Address of the owner of the minted token                                                               | yes      | env.message.sender   |
| public_metadata  | defined below              | The metadata that is publicly viewable                                                                 | yes      | nothing              |
| private_metadata | defined below              | The metadata that is viewable only by the token owner and addresses the owner has whitelisted          | yes      | nothing              |
| memo             | string                     | A memo for the mint transaction that is only viewable by addresses involved in the mint (minter/owner) | yes      | nothing              |
| padding          | string                     | An Ignored string that can be used to maintain constant message length                                 | yes      | nothing              |

### Metadata
Metadata for a token that follows CW-721 metadata specification, which is based on ERC721 Metadata JSON Schema.

| Name        | Type   | Description                                                           | Optional | Value If Omitted     |
|-------------|--------|-----------------------------------------------------------------------|----------|----------------------|
| name        | string | String that can be used to identify an asset's name                   | yes      | nothing              |
| description | string | String that can be used to describe an asset                          | yes      | nothing              |
| image       | string | String that can hold a link to additional off-chain metadata or image | yes      | nothing              |

##### Response
```
{
	"mint_nft": {
		"token_id": "ID_of_minted_token",
	}
}
```
The ID of the minted token will also be returned in a LogAttribute with the key `minted`.

## BatchMintNft
BatchMintNft mints a list of tokens.

##### Request
```
{
	"batch_mint_nft": {
		"mints": [
			"token_id": "optional_ID_of_new_token",
			"owner": "optional_address_the_new_token_will_be_minted_to",
			"public_metadata": {
				"name": "optional_public_name",
				"description": "optional_public_text_description",
				"image": "optional_public_uri_pointing_to_an_image_or_additional_off-chain_metadata"
			},
			"private_metadata": {
				"name": "optional_private_name",
				"description": "optional_private_text_description",
				"image": "optional_private_uri_pointing_to_an_image_or_additional_off-chain_metadata"
			},
			"memo": "optional_memo_for_the_mint_tx"
		],
		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name    | Type                      | Description                                                            | Optional | Value If Omitted |
|---------|---------------------------|------------------------------------------------------------------------|----------|------------------|
| mints   | array of Mint (see below) | A list of all the mint operations to perform                           | no       |                  |
| padding | string                    | An Ignored string that can be used to maintain constant message length | yes      | nothing          |

### Mint
Mint defines the data necessary to perform one minting operation

| Name             | Type                       | Description                                                                                            | Optional | Value If Omitted     |
|------------------|----------------------------|--------------------------------------------------------------------------------------------------------|----------|----------------------|
| token_id         | string                     | Identifier for the token to be minted                                                                  | yes      | minting order number |
| owner            | string (HumanAddr)         | Address of the owner of the minted token                                                               | yes      | env.message.sender   |
| public_metadata  | defined below              | The metadata that is publicly viewable                                                                 | yes      | nothing              |
| private_metadata | defined below              | The metadata that is viewable only by the token owner and addresses the owner has whitelisted          | yes      | nothing              |
| memo             | string                     | A memo for the mint transaction that is only viewable by addresses involved in the mint (minter/owner) | yes      | nothing              |

##### Response
```
{
	"batch_mint_nft": {
		"token_ids": [
			"IDs", "of", "tokens", "that", "were", "minted"
		]
	}
}
```
The IDs of the minted tokens will also be returned in a LogAttribute with the key `minted`.

## SetPublicMetadata
SetPublicMetadata will set the public metadata to the input metadata if the message sender is either the token owner or an approved minter and they have been given this power by the configuration value chosen during instantiation

##### Request
```
{
	"set_public_metadata": {
		"token_id": "ID_of_token_whose_metadata_should_be_updated",
		"metadata": {
			"name": "optional_public_name",
			"description": "optional_public_text_description",
			"image": "optional_public_uri_pointing_to_an_image_or_additional_off-chain_metadata"
		},
		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name     | Type                 | Description                                                            | Optional | Value If Omitted |
|----------|----------------------|------------------------------------------------------------------------|----------|------------------|
| token_id | string               | ID of the token whose metadata should be updated                       | no       |                  |
| metadata | Metadata (see above) | The new public metadata for the token                                  | no       |                  |
| padding  | string               | An Ignored string that can be used to maintain constant message length | yes      | nothing          |

## SetPrivateMetadata
SetPrivateMetadata will set the private metadata to the input metadata if the message sender is either the token owner or an approved minter and they have been given this power by the configuration value chosen during instantiation

##### Request
```
{
	"set_private_metadata": {
		"token_id": "ID_of_token_whose_metadata_should_be_updated",
		"metadata": {
			"name": "optional_private_name",
			"description": "optional_private_text_description",
			"image": "optional_private_uri_pointing_to_an_image_or_additional_off-chain_metadata"
		},
		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name     | Type                 | Description                                                            | Optional | Value If Omitted |
|----------|----------------------|------------------------------------------------------------------------|----------|------------------|
| token_id | string               | ID of the token whose metadata should be updated                       | no       |                  |
| metadata | Metadata (see above) | The new private metadata for the token                                 | no       |                  |
| padding  | string               | An Ignored string that can be used to maintain constant message length | yes      | nothing          |

## Reveal
Reveal unwraps the sealed metadata, irreversibly marking the token as unwrapped.  If the `unwrapped_metadata_is_private` configuration value is true, the formerly sealed metadata will remain private, otherwise it will be made public.

##### Request
```
{
	"reveal": {
		"token_id": "ID_of_the_token_to_unwrap",
		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name     | Type                 | Description                                                            | Optional | Value If Omitted |
|----------|----------------------|------------------------------------------------------------------------|----------|------------------|
| token_id | string               | ID of the token to unwrap                                              | no       |                  |
| padding  | string               | An Ignored string that can be used to maintain constant message length | yes      | nothing          |

## MakeOwnershipPrivate
MakeOwnershipPrivate is used when the token contract was instantiated with the `public_owner` configuration value set to true.  It allows an address to make all of its tokens have private ownership by default.  The owner may still use SetGlobalApproval or SetWhitelistedApproval to make ownership public as desired.

##### Request
```
{
	"make_ownership_public": {
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name     | Type                 | Description                                                            | Optional | Value If Omitted |
|----------|----------------------|------------------------------------------------------------------------|----------|------------------|
| padding  | string               | An Ignored string that can be used to maintain constant message length | yes      | nothing          |

## SetGlobalApproval
The owner of a token can use SetGlobalApproval to make ownership and/or private metadata viewable by everyone.  This can be set for a single token or for an owner's entire inventory of tokens by choosing the appropriate AccessLevel.  SetGlobalApproval can also be used to revoke any global approval previously granted.

##### Request
```
{
	"set_global_approval": {
		"token_id": "optional_ID_of_the_token_to_grant_or_revoke_approval_on",
		"view_owner": "approve_token"|"all"|"revoke_token"|"none",
		"view_private_metadata": "approve_token"|"all"|"revoke_token"|"none",
		"expires": "never"|{"at_height": 999999}|{"at_time":999999},
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name                  | Type                    | Description                                                                                          | Optional | Value If Omitted |
|-----------------------|-------------------------|------------------------------------------------------------------------------------------------------|----------|------------------|
| token_id              | string                  | If supplying either `approve_token` or `revoke_token` access, the token whose privacy is being set   | yes      | nothing          |
| view_owner            | AccessLevel (see below) | Grant or revoke everyone's permission to view the ownership of a token/inventory                     | yes      | nothing          |
| view_private_metadata | AccessLevel (see below) | Grant or revoke everyone's permission to view the private metadata of a token/inventory              | yes      | nothing          |
| expires               | Expiration (see below)  | The expiration of any approval granted in this message.  Can be set to a blockheight, time, or never | yes      | "never"          |
| padding               | string                  | An Ignored string that can be used to maintain constant message length                               | yes      | nothing          |

### AccessLevel
AccessLevel determines the type of access being granted or revoked to the specified address in a SetWhitelistedApproval message or to everyone in a SetGlobalApproval message.  The levels are mutually exclusive for any address (or for everyone if it is a global approval).  The levels are:
* `"approve_token"` - grant approval only on the token specified in the message
* `"revoke_token"` - revoke a previous approval on the specified token
* `"all"` - grant approval for all tokens in the message signer's inventory.  This approval will also apply to any tokens the signer acquires after granting `all` approval
* `"none"` - revoke any approval (both token and inventory-wide) previously granted to the specified address (or for everyone if using SetGlobalApproval)

If the message signer grants an address (or everyone in the case of SetGlobalApproval) `all` (inventory-wide) approval, it will remove any individual token approvals previously granted to that address (or granted to everyone in the case of SetGlobalApproval), and grant that address `all` (inventory-wide) approval.  If an address (or everyone in the case of SetGlobalApproval) already has `all` approval, and the message signer grants it `approve_token` approval, if the expiration of the new `approve_token` approval is the same as the expiration of the previous `all` approval, it will just leave the `all` approval in place.  If the expirations are different, it will grant `approve_token` approval with the specified expiration for the input token, and all other tokens will be changed to `approve_token` approvals with the expiration of the previous `all` approval, and the `all` (inventory-wide) approval will be removed.  If the message signer applies `revoke_token` access to an address that currently has inventory-wide approval, it will remove the inventory-wide approval, and create `approve_token` approvals for that address on every token in the signer's inventory EXCEPT the token specified with the `revoke_token` message.  In other words, it will only revoke the approval on that single token.

### Expiration
Expiration is used to set an expiration for any approvals granted in the message.  Expiration can be set to a specified blockheight, a time in seconds since epoch 01/01/1970, or "never".  Values for blockheight and time are specified as a u64.  If no expiration is given, it will default to "never".
* `"never"` - the approval will never expire
* `{"at_time": 1700000000}` - the approval will expire 1700000000 seconds after 01/01/1970 (time value is u64)
* `{"at_height": 3000000}` - the approval will expire at block height 3000000 (height value is u64)

## SetWhitelistedApproval
The owner of a token can use SetWhitelistedApproval to grant an address permission to view ownership, view private metadata, and/or to transfer a single token or every token in the owner's inventory.  SetWhitelistedApproval can also be used to revoke any approval previously granted to the address.

##### Request
```
{
	"set_whitelisted_approval": {
		"address": "address_being_granted_or_revoked_approval",
		"token_id": "optional_ID_of_the_token_to_grant_or_revoke_approval_on",
		"view_owner": "approve_token"|"all"|"revoke_token"|"none",
		"view_private_metadata": "approve_token"|"all"|"revoke_token"|"none",
		"transfer": "approve_token"|"all"|"revoke_token"|"none",
		"expires": "never"|{"at_height": 999999}|{"at_time":999999},
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name                  | Type                    | Description                                                                                          | Optional | Value If Omitted |
|-----------------------|-------------------------|------------------------------------------------------------------------------------------------------|----------|------------------|
| address               | string (HumanAddr)      | Address to grant or revoke approval to/from                                                          | no       |                  |
| token_id              | string                  | If supplying either `approve_token` or `revoke_token` access, the token whose privacy is being set   | yes      | nothing          |
| view_owner            | AccessLevel (see above) | Grant or revoke the address' permission to view the ownership of a token/inventory                   | yes      | nothing          |
| view_private_metadata | AccessLevel (see above) | Grant or revoke the address' permission to view the private metadata of a token/inventory            | yes      | nothing          |
| transfer              | AccessLevel (see above) | Grant or revoke the address' permission to transfer a token/inventory                                | yes      | nothing          |
| expires               | Expiration (see above)  | The expiration of any approval granted in this message.  Can be set to a blockheight, time, or never | yes      | "never"          |
| padding               | string                  | An Ignored string that can be used to maintain constant message length                               | yes      | nothing          |

## Approve
Approve is used to grant an address permission to transfer a single token.  Approve is provided to maintain compliance with CW-721, but the owner can use SetWhitelistedApproval to accomplish the same thing if specifying a `token_id` and `approve_token` AccessLevel for `transfer`.  Also, in compliance with CW-721, an address that has inventory-wide approval to transfer an owner's tokens, may use Approve to grant transfer approval of a single token to another address.

##### Request
```
{
	"approve": {
		"spender": "address_being_granted_approval_to_transfer_the_specified_token",
		"token_id": "ID_of_the_token_that_can_now_be_transferred_by_the_spender",
		"expires": "never"|{"at_height": 999999}|{"at_time":999999},
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name                  | Type                    | Description                                                                                          | Optional | Value If Omitted |
|-----------------------|-------------------------|------------------------------------------------------------------------------------------------------|----------|------------------|
| spender               | string (HumanAddr)      | Address being granted approval to transfer the token                                                 | no       |                  |
| token_id              | string                  | ID of the token that the spender can now transfer                                                    | no       |                  |
| expires               | Expiration (see above)  | The expiration of this token transfer approval                                                       | yes      | "never"          |
| padding               | string                  | An Ignored string that can be used to maintain constant message length                               | yes      | nothing          |

## Revoke
Revoke is used to revoke from an address the permission to transfer a single token.  Revoke is provided to maintain compliance with CW-721, but the owner can use SetWhitelistedApproval to accomplish the same thing if specifying a `token_id` and `revoke_token` AccessLevel for `transfer`.  Also, in compliance with CW-721, an address that has inventory-wide approval to transfer an owner's tokens (referred to as an operator later), may use Revoke to revoke transfer approval of a single token from another address.  However, one operator may not revoke transfer permission of even one single token away from another operator.

##### Request
```
{
	"revoke": {
		"spender": "address_being_revoked_approval_to_transfer_the_specified_token",
		"token_id": "ID_of_the_token_that_can_no_longer_be_transferred_by_the_spender",
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name                  | Type                    | Description                                                                                          | Optional | Value If Omitted |
|-----------------------|-------------------------|------------------------------------------------------------------------------------------------------|----------|------------------|
| spender               | string (HumanAddr)      | Address no longer permitted to transfer the token                                                    | no       |                  |
| token_id              | string                  | ID of the token that the spender can no longer transfer                                              | no       |                  |
| padding               | string                  | An Ignored string that can be used to maintain constant message length                               | yes      | nothing          |

## ApproveAll
ApproveAll is used to grant an address permission to transfer all the tokens in the message sender's inventory.  This will include the ability to transfer any tokens the sender acquires after granting this inventory-wide approval.  This also gives the address the ability to grant another address the approval to transfer a single token.  ApproveAll is provided to maintain compliance with CW-721, but the owner can use SetWhitelistedApproval to accomplish the same thing by using `all` AccessLevel for `transfer`.

##### Request
```
{
	"approve_all": {
		"operator": "address_being_granted_inventory-wide_approval_to_transfer_tokens",
		"expires": "never"|{"at_height": 999999}|{"at_time":999999},
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name                  | Type                    | Description                                                                                          | Optional | Value If Omitted |
|-----------------------|-------------------------|------------------------------------------------------------------------------------------------------|----------|------------------|
| operator              | string (HumanAddr)      | Address being granted approval to transfer all of the message sender's tokens                        | no       |                  |
| expires               | Expiration (see above)  | The expiration of this inventory-wide transfer approval                                              | yes      | "never"          |
| padding               | string                  | An Ignored string that can be used to maintain constant message length                               | yes      | nothing          |