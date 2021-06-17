SELECT uid,passwordRetryCount,cn,ou FROM @people WHERE passwordRetryCount>=3;
SELECT cn FROM @group WHERE memberuid=username;
@testquery;
