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
    "au-_vVPvv71K77-9z5Dvv70c77-9LO-_vTDvv73vv71n77-9BWDvv702HVZ077-977-9SADvv71J",
    "77-977-9fO-_ve-_vRfvv73vv70JeWNm77-9Fu-_vWLvv70S1Kvvv73vv73vv71Y77-9Oh5-EgBG"
  ]
}

disclosures = [
  "WyJzNnZtNTJzWjN3Y1NXNUEzIiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ",
  "WyJxZEt6MURIVDRlOHBpWlZ5IiwiaWQiLCIxMjM0Il0"
]
```