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
| Name               | Type                                                   | Description                                                         | Optional | Value If Omitted   |
|--------------------|--------------------------------------------------------|---------------------------------------------------------------------|----------|--------------------|
| name               | string                                                 | Name of the token contract                                          | no       |                    |
| symbol             | string                                                 | Token contract symbol                                               | no       |                    |
| admin              | string (HumanAddr)                                     | Address to be given admin authority                                 | yes      | env.message.sender |
| entropy            | string                                                 | String used as entropy when generating random viewing keys          | no       |                    |
| config             | [Config (see below)](### Config)                       | Privacy configuration for the contract                              | yes      | defined below      |
| post_init_callback | [PostInitCallback (see below)](### Post Init Callback) | Information used to perform a callback message after initialization | yes      | nothing            |

### Config
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

### Post Init Callback
Post)init_callback is the optional callback message to execute after the token contract has initialized.  This can be useful if another contract is instantiating this token contract and needs the token contract to inform the creating contract of the address it has been given

| Name             | Type                                  | Description                                                                                         | Optional | Value If Omitted |
|------------------|---------------------------------------|-----------------------------------------------------------------------------------------------------|----------|------------------|
| msg              | string (base64 encoded)               | Base64 encoded JSON representation of the callback message to perform after contract initialization | no       |                  |
| contract_address | string (HumanAddr)                    | Address of the contract to call after initialization                                                | no       |                  |
| code_hash        | string                                | Code hash of the contract to call after initialization                                              | no       |                  |
| send             | array of [Coin (see below)](#### Coin)| List of native Coin amounts to send with the callback message                                       | no       |                  |

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
| Name             | Type                                   | Description                                                                                   | Optional | Value If Omitted     |
|------------------|----------------------------------------|-----------------------------------------------------------------------------------------------|----------|----------------------|
| token_id         | string                                 | Identifier for the token to be minted                                                         | yes      | minting order number |
| owner            | string (HumanAddr)                     | Address of the owner of the minted token                                                      | yes      | env.message.sender   |
| public_metadata  | [Metadata (see below)](### Metadata)   | The metadata that is publicly viewable                                                        | yes      | nothing              |
| private_metadata | [Metadata (see below)](### Metadata)   | The metadata that is viewable only by the token owner and addresses the owner has whitelisted | yes      | nothing              |
| memo             | string                                 | A memo for the mint tx that is only viewable by addresses involved in the mint (minter/owner) | yes      | nothing              |
| padding          | string                                 | An Ignored string that can be used to maintain constant message length                        | yes      | nothing              |

##### Response
```
{
	"mint_nft": {
		"token_id": "ID_of_minted_token",
	}
}
```
The ID of the minted token will also be returned in a LogAttribute with the key `minted`.

### Metadata
Metadata for a token that follows CW-721 metadata specification, which is based on ERC721 Metadata JSON Schema.

| Name        | Type   | Description                                                           | Optional | Value If Omitted     |
|-------------|--------|-----------------------------------------------------------------------|----------|----------------------|
| name        | string | String that can be used to identify an asset's name                   | yes      | nothing              |
| description | string | String that can be used to describe an asset                          | yes      | nothing              |
| image       | string | String that can hold a link to additional off-chain metadata or image | yes      | nothing              |

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
| Name    | Type                                  | Description                                                            | Optional | Value If Omitted |
|---------|---------------------------------------|------------------------------------------------------------------------|----------|------------------|
| mints   | array of [Mint (see below)](### Mint) | A list of all the mint operations to perform                           | no       |                  |
| padding | string                                | An Ignored string that can be used to maintain constant message length | yes      | nothing          |

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

### Mint
Mint defines the data necessary to perform one minting operation

| Name             | Type                                 | Description                                                                                        | Optional | Value If Omitted     |
|------------------|--------------------------------------|----------------------------------------------------------------------------------------------------|----------|----------------------|
| token_id         | string                               | Identifier for the token to be minted                                                              | yes      | minting order number |
| owner            | string (HumanAddr)                   | Address of the owner of the minted token                                                           | yes      | env.message.sender   |
| public_metadata  | [Metadata (see above)](### Metadata) | The metadata that is publicly viewable                                                             | yes      | nothing              |
| private_metadata | [Metadata (see above)](### Metadata) | The metadata that is viewable only by the token owner and addresses the owner has whitelisted      | yes      | nothing              |
| memo             | string                               | A memo for the mint tx that is only viewable by addresses involved in the mint (minter/owner)      | yes      | nothing              |

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
| Name     | Type                                 | Description                                                            | Optional | Value If Omitted |
|----------|--------------------------------------|------------------------------------------------------------------------|----------|------------------|
| token_id | string                               | ID of the token whose metadata should be updated                       | no       |                  |
| metadata | [Metadata (see above)](### Metadata) | The new public metadata for the token                                  | no       |                  |
| padding  | string                               | An Ignored string that can be used to maintain constant message length | yes      | nothing          |

##### Response
```
{
	"set_public_metadata": {
		"status": "success"
	}
}
```

## SetPrivateMetadata
SetPrivateMetadata will set the private metadata to the input metadata if the message sender is either the token owner or an approved minter and they have been given this power by the configuration value chosen during instantiation.  The private metadata of a sealed token may not be altered until after it has been unwrapped.

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
| Name     | Type                                 | Description                                                            | Optional | Value If Omitted |
|----------|--------------------------------------|------------------------------------------------------------------------|----------|------------------|
| token_id | string                               | ID of the token whose metadata should be updated                       | no       |                  |
| metadata | [Metadata (see above)](### Metadata) | The new private metadata for the token                                 | no       |                  |
| padding  | string                               | An Ignored string that can be used to maintain constant message length | yes      | nothing          |

##### Response
```
{
	"set_private_metadata": {
		"status": "success"
	}
}
```

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

##### Response
```
{
	"reveal": {
		"status": "success"
	}
}
```

## MakeOwnershipPrivate
MakeOwnershipPrivate is used when the token contract was instantiated with the `public_owner` configuration value set to true.  It allows an address to make all of its tokens have private ownership by default.  The owner may still use SetGlobalApproval or SetWhitelistedApproval to make ownership public as desired.

##### Request
```
{
	"make_ownership_private": {
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name     | Type                 | Description                                                            | Optional | Value If Omitted |
|----------|----------------------|------------------------------------------------------------------------|----------|------------------|
| padding  | string               | An Ignored string that can be used to maintain constant message length | yes      | nothing          |

##### Response
```
{
	"make_ownership_private": {
		"status": "success"
	}
}
```

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
| Name                  | Type                                       | Description                                                                                        | Optional | Value If Omitted |
|-----------------------|--------------------------------------------|----------------------------------------------------------------------------------------------------|----------|------------------|
| token_id              | string                                     | If supplying either `approve_token` or `revoke_token` access, the token whose privacy is being set | yes      | nothing          |
| view_owner            | [AccessLevel (see below)](### AccessLevel) | Grant or revoke everyone's permission to view the ownership of a token/inventory                   | yes      | nothing          |
| view_private_metadata | [AccessLevel (see below)](### AccessLevel) | Grant or revoke everyone's permission to view the private metadata of a token/inventory            | yes      | nothing          |
| expires               | [Expiration (see below)](### Expiration)   | Expiration of any approval granted in this message.  Can be a blockheight, time, or never          | yes      | "never"          |
| padding               | string                                     | An Ignored string that can be used to maintain constant message length                             | yes      | nothing          |

##### Response
```
{
	"set_global_approval": {
		"status": "success"
	}
}
```
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
| Name                  | Type                                       | Description                                                                                        | Optional | Value If Omitted |
|-----------------------|--------------------------------------------|----------------------------------------------------------------------------------------------------|----------|------------------|
| address               | string (HumanAddr)                         | Address to grant or revoke approval to/from                                                        | no       |                  |
| token_id              | string                                     | If supplying either `approve_token` or `revoke_token` access, the token whose privacy is being set | yes      | nothing          |
| view_owner            | [AccessLevel (see above)](### AccessLevel) | Grant or revoke the address' permission to view the ownership of a token/inventory                 | yes      | nothing          |
| view_private_metadata | [AccessLevel (see above)](### AccessLevel) | Grant or revoke the address' permission to view the private metadata of a token/inventory          | yes      | nothing          |
| transfer              | [AccessLevel (see above)](### AccessLevel) | Grant or revoke the address' permission to transfer a token/inventory                              | yes      | nothing          |
| expires               | [Expiration (see above)](### Expiration)   | The expiration of any approval granted in this message.  Can be a blockheight, time, or never      | yes      | "never"          |
| padding               | string                                     | An Ignored string that can be used to maintain constant message length                             | yes      | nothing          |

##### Response
```
{
	"set_whitelisted_approval": {
		"status": "success"
	}
}
```

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
| Name                  | Type                                     | Description                                                                                          | Optional | Value If Omitted |
|-----------------------|------------------------------------------|------------------------------------------------------------------------------------------------------|----------|------------------|
| spender               | string (HumanAddr)                       | Address being granted approval to transfer the token                                                 | no       |                  |
| token_id              | string                                   | ID of the token that the spender can now transfer                                                    | no       |                  |
| expires               | [Expiration (see above)](### Expiration) | The expiration of this token transfer approval                                                       | yes      | "never"          |
| padding               | string                                   | An Ignored string that can be used to maintain constant message length                               | yes      | nothing          |

##### Response
```
{
	"approve": {
		"status": "success"
	}
}
```

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

##### Response
```
{
	"revoke": {
		"status": "success"
	}
}
```

## ApproveAll
ApproveAll is used to grant an address permission to transfer all the tokens in the message sender's inventory.  This will include the ability to transfer any tokens the sender acquires after granting this inventory-wide approval.  This also gives the address the ability to grant another address the approval to transfer a single token.  ApproveAll is provided to maintain compliance with CW-721, but the message sender can use SetWhitelistedApproval to accomplish the same thing by using `all` AccessLevel for `transfer`.

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
| Name                  | Type                                     | Description                                                                                          | Optional | Value If Omitted |
|-----------------------|------------------------------------------|------------------------------------------------------------------------------------------------------|----------|------------------|
| operator              | string (HumanAddr)                       | Address being granted approval to transfer all of the message sender's tokens                        | no       |                  |
| expires               | [Expiration (see above)](### Expiration) | The expiration of this inventory-wide transfer approval                                              | yes      | "never"          |
| padding               | string                                   | An Ignored string that can be used to maintain constant message length                               | yes      | nothing          |

##### Response
```
{
	"approve_all": {
		"status": "success"
	}
}
```

## RevokeAll
RevokeAll is used to revoke an inventory-wide transfer approval granted to an address.  RevokeAll is provided to maintain compliance with CW-721, but the message sender can use SetWhitelistedApproval to accomplish the same thing by using `none` AccessLevel for `transfer`.

##### Request
```
{
	"revoke_all": {
		"operator": "address_being_revoked_a_previous_inventory-wide_approval_to_transfer_tokens",
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name                  | Type                    | Description                                                                                          | Optional | Value If Omitted |
|-----------------------|-------------------------|------------------------------------------------------------------------------------------------------|----------|------------------|
| operator              | string (HumanAddr)      | Address being revoked a previous approval to transfer all of the message sender's tokens             | no       |                  |
| padding               | string                  | An Ignored string that can be used to maintain constant message length                               | yes      | nothing          |

##### Response
```
{
	"revoke_all": {
		"status": "success"
	}
}
```

## TransferNft
TransferNft is used to transfer a token to the recipient address.  The token owner and anyone else with valid transfer approval may use TransferNft.  If the recipient address is the same as the current owner, no transfer will be done (transaction history will not include a transfer that does not change ownership).  If the token is transferred to a new owner, its single-token approvals will be cleared.

##### Request
```
{
	"transfer_nft": {
		"recipient": "address_receiving_the_token",
		"token_id": "ID_of_the_token_being_transferred",
		"memo": "optional_memo_for_the_transfer_tx",
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name      | Type               | Description                                                                                                                       | Optional | Value If Omitted |
|-----------|--------------------|-----------------------------------------------------------------------------------------------------------------------------------|----------|------------------|
| recipient | string (HumanAddr) | Address receiving the token                                                                                                       | no       |                  |
| token_id  | string             | Identifier of the token to be transferred                                                                                         | no       |                  |
| memo      | string             | Memo for the transfer transaction that is only viewable by addresses involved in the transfer (recipient, sender, previous owner) | yes      | nothing          |
| padding   | string             | An Ignored string that can be used to maintain constant message length                                                            | yes      | nothing          |

##### Response
```
{
	"transfer_nft": {
		"status": "success"
	}
}
```

## BatchTransferNft
BatchTransferNft is used to perform multiple token transfers.  The message sender may specify a list of tokens to transfer to one recipient address in each `Transfer` object, and any `memo` provided will be applied to every token transferred in that one `Transfer` object.  The message sender may provide multiple `Transfer` objects to perform transfers to multiple addresses, providing a different memo for each address if desired.  Each individual transfer of a token will show separately in transaction histories.  The message sender must have permission to transfer all the tokens listed (either by being the owner or being granted transfer approval).  A contract may use the VerifyTransferApproval query to verify that it has permission to transfer all the tokens.  If the message sender does not have permission to transfer any one of the listed tokens, the entire message will fail (no tokens will be transferred) and the error will provide the ID of the first token encountered in which the sender does not have the required permission.  If any token transfer involves a recipient address that is the same as its current owner, that transfer will not be done (transaction history will not include a transfer that does not change ownership), but all the other transfers will proceed.  Any token that is transferred to a new owner will have its single-token approvals cleared.

##### Request
```
{
	"batch_transfer_nft": {
		"transfers": [
			"recipient": "address_receiving_the_tokens",
			"token_ids": [
				"list", "of", "token", "IDs", "to", "transfer"
			],
			"memo": "optional_memo_applied_to_the_transfer_tx_for_every_token_listed_in_this_Transfer_object"
		],
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name      | Type                                          | Description                                                                                          | Optional | Value If Omitted |
|-----------|-----------------------------------------------|------------------------------------------------------------------------------------------------------|----------|------------------|
| transfers | array of [Transfer (see below)](### Transfer) | List of `Transfer` objects to process                                                                | no       |                  |
| padding   | string                                        | An Ignored string that can be used to maintain constant message length                               | yes      | nothing          |

##### Response
```
{
	"batch_transfer_nft": {
		"status": "success"
	}
}
```

### Transfer
The Transfer object provides a list of tokens to transfer to one recipient address, as well as an optional memo that would be included with every logged token transfer.

| Name      | Type               | Description                                                                                                                       | Optional | Value If Omitted |
|-----------|--------------------|-----------------------------------------------------------------------------------------------------------------------------------|----------|------------------|
| recipient | string (HumanAddr) | Address receiving the listed tokens                                                                                               | no       |                  |
| token_ids | array of string    | List of token IDs to transfer to the recipient                                                                                    | no       |                  |
| memo      | string             | Memo for the transfer transactions that is only viewable by addresses involved in the transfer (recipient, sender, previous owner)| yes      | nothing          |

## SendNft
SendNft is used to transfer a token to the recipient address, and then call the recipient's ReceiveNft (or BatchReceiveNft, [see below](# Receiver Interface)) if the recipient contract has registered its receive functionality with the NFT contract.  If the recipient contract registered that it implements BatchReceiveNft, a BatchReceiveNft callback will be performed with only the single token ID in the `token_ids` array.  The token owner and anyone else with valid transfer approval may use SendNft.  If the recipient address is the same as the current owner, no transfer will be done (transaction history will not include a transfer that does not change ownership), but the ReceiveNft (or BatchReceiveNft) callback will be performed if registered.  If the token is transferred to a new owner, its single-token approvals will be cleared.  If the ReceiveNft (or BatchReceiveNft) callback fails, the entire transaction will be reverted (even the transfer will not take place).

##### Request
```
{
	"send_nft": {
		"contract": "address_receiving_the_token",
		"token_id": "ID_of_the_token_being_transferred",
		"msg": "optional_base64_encoded_message_string_sent_with_the_ReceiveNft_callback",
		"memo": "optional_memo_for_the_transfer_tx",
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name     | Type                     | Description                                                                                                                   | Optional | Value If Omitted |
|----------|--------------------------|-------------------------------------------------------------------------------------------------------------------------------|----------|------------------|
| contract | string (HumanAddr)       | Address receiving the token                                                                                                   | no       |                  |
| token_id | string                   | Identifier of the token to be transferred                                                                                     | no       |                  |
| msg      | string (base64 encoded)  | Msg included when calling the recipient contract's ReceiveNft (or BatchReceiveNft)                                            | yes      | nothing          |
| memo     | string                   | Memo for the transfer tx that is only viewable by addresses involved in the transfer (recipient, sender, previous owner)      | yes      | nothing          |
| padding  | string                   | An Ignored string that can be used to maintain constant message length                                                        | yes      | nothing          |

##### Response
```
{
	"send_nft": {
		"status": "success"
	}
}
```

## BatchSendNft
BatchSendNft is used to perform multiple token transfers, and then call the recipient contracts' BatchReceiveNft (or ReceiveNft [see below](# Receiver Interface)) if they have registered their receive functionality with the NFT contract.  The message sender may specify a list of tokens to send to one recipient address in each `Send` object, and any `memo` or `msg` provided will be applied to every token transferred in that one `Send` object.  If the list of transferred tokens belonged to multiple previous owners, a separate BatchReceiveNft callback will be performed for each of the previous owners.  If the contract only implements ReceiveNft, one ReceiveNft will be performed for every sent token.  Therefore it is highly recommended to implement BatchReceiveNft if there is the possibility of being sent multiple tokens at one time.  This will reduce gas costs by around 80k per token sent.  

The message sender may provide multiple `Send` objects to perform sends to multiple addresses, providing a different `memo` and `msg` for each address if desired.  Each individual transfer of a token will show separately in transaction histories.  The message sender must have permission to transfer all the tokens listed (either by being the owner or being granted transfer approval).  A contract may use the VerifyTransferApproval query to verify that it has permission to transfer all the tokens.  If the message sender does not have permission to transfer any one of the listed tokens, the entire message will fail (no tokens will be transferred) and the error will provide the ID of the first token encountered in which the sender does not have the required permission.  If any token transfer involves a recipient address that is the same as its current owner, that transfer will not be done (transaction history will not include a transfer that does not change ownership), but all the other transfers will proceed.  Any token that is transferred to a new owner will have its single-token approvals cleared.
If any BatchReceiveNft (or ReceiveNft) callback fails, the entire transaction will be reverted (even the transfers will not take place).
See the bottom of this document for the definitions of BatchReceiveNft and ReceiveNft messages.

##### Request
```
{
	"batch_send_nft": {
		"sends": [
			"contract": "address_receiving_the_tokens",
			"token_ids": [
				"list", "of", "token", "IDs", "to", "transfer"
			],
			"msg": "optional_base64_encoded_message_string_sent_with_every_BatchReceiveNft_callback_made_for_this_one_Send_object",
			"memo": "optional_memo_applied_to_the_transfer_tx_for_every_token_listed_in_this_Send_object"
		],
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name      | Type                                  | Description                                                                                                        | Optional | Value If Omitted |
|-----------|---------------------------------------|--------------------------------------------------------------------------------------------------------------------|----------|------------------|
| sends     | array of [Send (see below)](### Send) | List of `Send` objects to process                                                                                  | no       |                  |
| padding   | string                                | An Ignored string that can be used to maintain constant message length                                             | yes      | nothing          |

##### Response
```
{
	"batch_send_nft": {
		"status": "success"
	}
}
```

### Send
The Send object provides a list of tokens to transfer to one recipient address, as well as an optional memo that would be included with every logged token transfer, and an optional msg that would be included with every BatchReceiveNft or ReceiveNft ([see below](# Receiver Interface)) callback made as a result of this Send object.

| Name      | Type                    | Description                                                                                                                  | Optional | Value If Omitted |
|-----------|-------------------------|------------------------------------------------------------------------------------------------------------------------------|----------|------------------|
| contract  | string (HumanAddr)      | Address receiving the listed tokens                                                                                          | no       |                  |
| token_ids | array of string         | List of token IDs to send to the recipient                                                                                   | no       |                  |
| msg       | string (base64 encoded) | Msg included with every BatchReceiveNft (or ReceiveNft) callback performed for this `Send` object                            | yes      | nothing          |
| memo      | string                  | Memo for the transfer txs that is only viewable by addresses involved in the transfer (recipient, sender, previous owner)    | yes      | nothing          |

## BurnNft
BurnNft is used to burn a single token, providing an optional memo to include in the burn's transaction history if desired.  If the contract has not enabled burn functionality using the init configuration `enable_burn`, BurnNft will result in an error.  The token owner and anyone else with valid transfer approval may use BurnNft.

##### Request
```
{
	"burn_nft": {
		"token_id": "ID_of_the_token_to_burn",
		"memo": "optional_memo_for_the_burn_tx",
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name      | Type               | Description                                                                                                                       | Optional | Value If Omitted |
|-----------|--------------------|-----------------------------------------------------------------------------------------------------------------------------------|----------|------------------|
| token_id  | string             | Identifier of the token to burn                                                                                                   | no       |                  |
| memo      | string             | Memo for the burn tx that is only viewable by addresses involved in the burn (message sender and previous owner if different)     | yes      | nothing          |
| padding   | string             | An Ignored string that can be used to maintain constant message length                                                            | yes      | nothing          |

##### Response
```
{
	"burn_nft": {
		"status": "success"
	}
}
```

## BatchBurnNft
BatchBurnNft is used to burn multiple tokens.  The message sender may specify a list of tokens to burn in each `Burn` object, and any `memo` provided will be applied to every token burned in that one `Burn` object.  The message sender will usually list every token to be burned in one `Burn` object, but if a different memo is needed for different tokens being burned, multiple `Burn` objects may be listed. Each individual burning of a token will show separately in transaction histories.  The message sender must have permission to transfer/burn all the tokens listed (either by being the owner or being granted transfer approval).  A contract may use the VerifyTransferApproval query to verify that it has permission to transfer/burn all the tokens.  If the message sender does not have permission to transfer/burn any one of the listed tokens, the entire message will fail (no tokens will be burned) and the error will provide the ID of the first token encountered in which the sender does not have the required permission.

##### Request
```
{
	"batch_burn_nft": {
		"burns": [
			"token_ids": [
				"list", "of", "token", "IDs", "to", "burn"
			],
			"memo": "optional_memo_applied_to_the_burn_tx_for_every_token_listed_in_this_Burn_object"
		],
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name      | Type                                  | Description                                                                                                        | Optional | Value If Omitted |
|-----------|---------------------------------------|--------------------------------------------------------------------------------------------------------------------|----------|------------------|
| burns     | array of [Burn (see below)](### Burn) | List of `Burn` objects to process                                                                                  | no       |                  |
| padding   | string                                | An Ignored string that can be used to maintain constant message length                                             | yes      | nothing          |

##### Response
```
{
	"batch_burn_nft": {
		"status": "success"
	}
}
```

### Burn
The Burn object provides a list of tokens to burn, as well as an optional memo that would be included with every token burn transaction history.

| Name      | Type            | Description                                                                                                                    | Optional | Value If Omitted |
|-----------|-----------------|--------------------------------------------------------------------------------------------------------------------------------|----------|------------------|
| token_ids | array of string | List of token IDs to burn                                                                                                      | no       |                  |
| memo      | string          | Memo for the burn txs that is only viewable by addresses involved in the burn (message sender and previous owner if different) | yes      | nothing          |

## CreateViewingKey
CreateViewingKey is used to generate a random viewing key to be used to authenticate account-specific queries.  The `entropy` field is a client-supplied string used as part of the entropy supplied to the rng that creates the viewing key.

##### Request
```
{
	"create_viewing_key": {
		"entropy": "string_used_as_part_of_the_entropy_supplied_to_the_rng",
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name      | Type   | Description                                                                                                        | Optional | Value If Omitted |
|-----------|--------|--------------------------------------------------------------------------------------------------------------------|----------|------------------|
| entropy   | string | String used as part of the entropy supplied to the rng that generates the random viewing key                       | no       |                  |
| padding   | string | An Ignored string that can be used to maintain constant message length                                             | yes      | nothing          |

##### Response
```
{
	"viewing_key": {
		"key": "the_created_viewing_key"
	}
}
```

## SetViewingKey
SetViewingKey is used to set the viewing key to a predefined string.  It will replace any key that currently exists.  It would be best for users to call CreateViewingKey to ensure a strong key, but this function is provided so that contracts can also utilize viewing keys.

##### Request
```
{
	"set_viewing_key": {
		"key": "the_new_viewing_key",
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name      | Type   | Description                                                                                                        | Optional | Value If Omitted |
|-----------|--------|--------------------------------------------------------------------------------------------------------------------|----------|------------------|
| key       | string | The new viewing key for the message sender                                                                         | no       |                  |
| padding   | string | An Ignored string that can be used to maintain constant message length                                             | yes      | nothing          |

##### Response
```
{
	"viewing_key": {
		"key": "the_message_sender's_viewing_key"
	}
}
```

## AddMinters
AddMinters will add the provided addresses to the list of authorized minters.  This can only be called by the admin address.

##### Request
```
{
	"add_minters": {
		"minters": [
			"list", "of", "addresses", "to", "add", "to", "the", "list", "of", "minters"
		],
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name    | Type                        | Description                                                                                                        | Optional | Value If Omitted |
|---------|-----------------------------|--------------------------------------------------------------------------------------------------------------------|----------|------------------|
| minters | array of string (HumanAddr) | The list of addresses to add to the list of authorized minters                                                     | no       |                  |
| padding | string                      | An Ignored string that can be used to maintain constant message length                                             | yes      | nothing          |

##### Response
```
{
	"add_minters": {
		"status": "success"
	}
}
```

## RemoveMinters
RemoveMinters will remove the provided addresses from the list of authorized minters.  This can only be called by the admin address.

##### Request
```
{
	"remove_minters": {
		"minters": [
			"list", "of", "addresses", "to", "remove", "from", "the", "list", "of", "minters"
		],
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name    | Type                        | Description                                                                                                        | Optional | Value If Omitted |
|---------|-----------------------------|--------------------------------------------------------------------------------------------------------------------|----------|------------------|
| minters | array of string (HumanAddr) | The list of addresses to remove from the list of authorized minters                                                | no       |                  |
| padding | string                      | An Ignored string that can be used to maintain constant message length                                             | yes      | nothing          |

##### Response
```
{
	"remove_minters": {
		"status": "success"
	}
}
```

## SetMinters
SetMinters will precisely define the list of authorized minters.  This can only be called by the admin address.

##### Request
```
{
	"set_minters": {
		"minters": [
			"list", "of", "addresses", "that", "have", "minting", "authority"
		],
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name    | Type                        | Description                                                                                 | Optional | Value If Omitted |
|---------|-----------------------------|---------------------------------------------------------------------------------------------|----------|------------------|
| minters | array of string (HumanAddr) | The list of addresses to are allowed to mint                                                | no       |                  |
| padding | string                      | An Ignored string that can be used to maintain constant message length                      | yes      | nothing          |

##### Response
```
{
	"set_minters": {
		"status": "success"
	}
}
```

## SetContractStatus
SetContractStatus allows the contract admin to define which messages the contract will execute.  This can only be called by the admin address.

##### Request
```
{
	"set_contract_status": {
		"level": "normal"|"stop_transactions"|"stop_all",
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name    | Type                                             | Description                                                                                 | Optional | Value If Omitted |
|---------|--------------------------------------------------|---------------------------------------------------------------------------------------------|----------|------------------|
| level   | [ContractStatus (see below)](### ContractStatus) | The level that defines which messages the contract will execute                             | no       |                  |
| padding | string                                           | An Ignored string that can be used to maintain constant message length                      | yes      | nothing          |

##### Response
```
{
	"set_contract_status": {
		"status": "success"
	}
}
```
### ContractStatus
ContractStatus indicates which messages the contract will execute. The possible values are:
* `"normal"` - the contract will execute all messages
* `"stop_transactions"` - the contract will not allow any minting, burning, sending, or transferring of tokens
* `"stop_all"` - the contract will only execute a SetContractStatus message

## ChangeAdmin
ChangeAdmin will allow the current admin to transfer admin privileges to another address (which will be the only admin address).  This can only be called by the current admin address.

##### Request
```
{
	"change_admin": {
		"address": "address_of_the_new_contract_admin",
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name    | Type               | Description                                                                                 | Optional | Value If Omitted |
|---------|--------------------|---------------------------------------------------------------------------------------------|----------|------------------|
| address | string (HumanAddr) | Address of the new contract admin                                                           | no       |                  |
| padding | string             | An Ignored string that can be used to maintain constant message length                      | yes      | nothing          |

##### Response
```
{
	"change_admin": {
		"status": "success"
	}
}
```

## RegisterReceiveNft
A contract will use RegisterReceiveNft to notify the NFT contract that it implements ReceiveNft and possibly also BatchReceiveNft [(see below)](# Receiver Interface).  This enables the NFT contract to call the registered contract whenever it is Sent a token (or tokens).  ReceiveNft only informs the recipient contract that it has been sent a single token; while, BatchReceiveNft can be used to inform a contract that it was sent multiple tokens.  This is particularly useful if a contract needs to be sent a deck of "cards", as it will save around 80k in gas for every token that was sent.  If a contract implements BatchReceiveNft, the NFT contract will always call BatchReceiveNft even if there is only one token being sent, in which case the `token_ids` array will only have one element.

##### Request
```
{
	"register_receive_nft": {
		"code_hash": "code_hash_of_the_contract_implementing_a_receiver_interface",
		"also_implements_batch_receive_nft": true|false,
 		"padding": "optional_ignored_string_that_can_be_used_to_maintain_constant_message_length"
	}
}
```
| Name                              | Type   | Description                                                                                                                | Optional | Value If Omitted |
|-----------------------------------|--------|----------------------------------------------------------------------------------------------------------------------------|----------|------------------|
| code_hash                         | string | Code hash of the message sender, which is a contract that implements a receiver interface                                  | no       |                  |
| also_implements_batch_receive_nft | bool   | true if the message sender contract also implements BatchReceiveNft so it can be informed that it was sent a list of tokens| yes      | false            |
| padding                           | string | An Ignored string that can be used to maintain constant message length                                                     | yes      | nothing          |

##### Response
```
{
	"register_receive_nft": {
		"status": "success"
	}
}
```

# Receiver Interface