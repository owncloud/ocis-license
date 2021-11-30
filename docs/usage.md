# Usage

Create a root certificate:  
`./ocis-license certificate create -profile root-ca "ownCloud GmbH" rootCA.crt rootCa.key`

Create an intermediate certificate:  
`./ocis-license certificate create -profile intermediate-ca -ca rootCA.crt -ca-key rootCA.key "ownCloud GmbH" intermediateCA.crt intermediateCA.key`

Generate a new license:  
`./ocis-license license create -signing-cert intermediateCA.crt -signing-key intermediateCA.key -payload-template payload.json`

To generate a license you need to provide a payload template, which contains the data of the license.

Here is an example:
```json
{
    "id": "8d402b74-581a-49c0-ab43-b19e60464d7d",
    "environment": "development",
    "type": "non-commercial",
    "features": ["core", "special-thumbnails", "reports"],
    "sla_type": "none",
    "origin": "ownCloud GmbH",
    "grace_periods": {
	"1": "+30d",
	"2": "+60d",
	"3": "+90d"
    }
}
```

The reason for the template is that it is simpler than having the json as a command argument or having many flags.

And to verify a license you can just run:  
`./ocis-license license verify -root-cert rootCA.crt eyJ2ZXJzaW9uIjoiMSIsInBheWxvYWRfc2lnbmF0dXJlIjoiLzNnbHorSXQvcm5ZNjJQL1VJY0h3bSswMEpmUkZyRWJhK3J0L1VJK3g3VnovQ1pTcXJDalFLREkrRCs0Q21SMDc0WitxSWZoVThMVEVpOHJ2YkFBREE9PSIsImNlcnRpZmljYXRlIjoiTUlJQklEQ0IwNkFEQWdFQ0FnRVRNQVVHQXl0bGNEQVlNUll3RkFZRFZRUURFdzF2ZDI1RGJHOTFaQ0JIYldKSU1CNFhEVEl4TVRFeU5URTFOVFF6TWxvWERUSXpNVEV5TlRFMU5UUXpNbG93R0RFV01CUUdBMVVFQXhNTmIzZHVRMnh2ZFdRZ1IyMWlTREFxTUFVR0F5dGxjQU1oQUdMbWUwTTJOcXp1ZS9EbVd2WHZrSGFuUXk3NkJyMUZXVUlIOVhuVm12RzNvMEl3UURBT0JnTlZIUThCQWY4RUJBTUNBWVl3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFkQmdOVkhRNEVGZ1FVSkVxZjN0OEkzbnE1VE0wd21VaTdZa3dSTjhJd0JRWURLMlZ3QTBFQVBZaHNmdTNmMlZRNG5IekNtSzRYZkJSQzVlQkkyZnVweWNvRWxLRm5GbmJPemZ6NWRwTkdVOWhodzBZczd1ZUVTVmRZbXFvTkJiL3YwN1B1Z1R3SkR3PT0ifQ==.eyJpZCI6IjhkNDAyYjc0LTU4MWEtNDljMC1hYjQzLWIxOWU2MDQ2NGQ3ZCIsInR5cGUiOiJub24tY29tbWVyY2lhbCIsImVudmlyb25tZW50IjoiZGV2ZWxvcG1lbnQiLCJjcmVhdGVkIjoiMjAyMS0xMS0yNVQxNzozMTo0MC44ODQ0NTE4NDUrMDE6MDAiLCJmZWF0dXJlcyI6WyJjb3JlIiwic3BlY2lhbC10aHVtYm5haWxzIiwicmVwb3J0cyJdLCJzbGFfdHlwZSI6Im5vbmUiLCJvcmlnaW4iOiJvd25DbG91ZCBHbWJIIiwiZ3JhY2VfcGVyaW9kcyI6eyIxIjoiKzMwZCIsIjIiOiIrNjBkIiwiMyI6Iis5MGQifSwiYWRkaXRpb25hbCI6bnVsbH0=`