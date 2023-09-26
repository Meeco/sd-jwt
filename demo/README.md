## Basic Usage

### Issuance
Inputs:
* `example/claims.json`: payload  
* `example/claims.sd.json`: DisclosureFrame

```
npm run issue
```
Outputs:
* `output/disclosures.md`: lists the disclosures and its hash digests
* `output/issued.json`: issued sd-jwt payload in JSON format
* `output/issued.jwt`: issued compact sd-jwt
* `output/presentation.jwt`: copy of `issued.jwt` to allow removal of disclosures and used in verification


### Verification
Inputs:
* `output/presentation.jwt`: compact sd-jwt

```
npm run verify
```
Outputs:
* `output/disclosed.json`: verified sd-jwt with disclosed claims in JSON format

