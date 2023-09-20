This is an implementation of [SD-JWT (I-D version 05)](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html) in typescript.


### Test

Runs against examples in `test/examples` directory

Examples are generated using [`sd-jwt-generate`](https://github.com/openwallet-foundation-labs/sd-jwt-python)
```
npm run test
```

# packSDJWT Examples

The `packSDJWT` function takes a claims object and disclosure frame and returns packed claims with selective disclosures encrypted.

## Basic Usage

```js
import { packSDJWT } from 'sd-jwt';

const claims = {
  name: 'Jane',
  ssn: '123-45-6789'    
};

const disclosureFrame = {
  _sd: ['ssn']   
};

const {claims: packed, disclosures} = await packSDJWT(claims, disclosureFrame, hasher);
```

This will selectively disclose `ssn` and return the packed claims and disclosures array.


## Disclosing Multiple Claims

To selectively disclose multiple claims:

```js
const claims = {
  name: 'Jane Doe',
  ssn: '123-45-6789',
  id: '1234'   
};

const disclosureFrame = {
  _sd: ['ssn', 'id']  
};

const {claims: packed, disclosures} = await packSDJWT(claims, disclosureFrame, hasher);

// Results
packed =  {
  "name": "Jane Doe",
  "_sd": [
      "DZkUdg_W43hB25uuSxEyt2ialCeDbweHVXcRrhQHbLY",
      "85kfxIj8lWd5WODcupbDiYEw6upYWoD1GI048JUVAHw"
  ]
}

disclosures = [
  "WyJzNnZtNTJzWjN3Y1NXNUEzIiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ",
  "WyJxZEt6MURIVDRlOHBpWlZ5IiwiaWQiLCIxMjM0Il0"
]
```

## Selective Disclosable items in array

```js
const claims = {
  items: ['a', 'b', 'c'] 
};

const disclosureFrame = {
  items: { _sd: 1 } // item at index 1
}

const {claims: packedClaims, disclosures} = await packSDJWT(claims, disclosureFrame, hasher);

// Results
packedClaims = {
  items: [
    'a', 
    {
      "...": "b64encodedhash" 
    },
    'c'
  ]
}

disclosures = [
  "WyJzYWx0IiwgMV0=" // b64 encoded [salt, 1]
]
```

## Combinations

```js
const claims = {
  arrayInArray: [[1, 2], [3, 4]],
  objectInArray: [{id: 1}, {id: 2}],
  combo: [[1, {id: 2}], [{id:3}, 4]]
};

const disclosureFrame = {
  arrayInArray: {
    0: { _sd: [0] },
    1: { _sd: [1] }
  },
  objectInArray: [
    {_sd: ['id']}, 
    {_sd: ['id']}
  ],
  combo: {
    0: {
      _sd: [0],
      1: { _sd: ['id'] }
    },
    1: {
      0: { _sd: ['id'] }
    }
  }
};

const {claims: packedClaims, disclosures} = await packSDJWT(claims, disclosureFrame, hasher);

// packedClaims
{
  arrayInArray: [[{...: 'abc123'}, 2], [3, {...: 'def456'}]],
  objectInArray: [{_sd: ['xyz789']}, {_sd: ['uvw012']}], 
  combo: [[{...: 'ghi345'}, {_sd: ['jkl678']}], [{_sd: ['mno901']}, 4]]
}

// disclosures 
[
  'abc123', // arrayInArray[0][0]
  'def456', // arrayInArray[1][1]
  'xyz789', // objectInArray[0].id
  'uvw012', // objectInArray[1].id
  'ghi345', // combo[0][0] 
  'jkl678', // combo[0][1].id
  'mno901', // combo[1][0].id
]
```