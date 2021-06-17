# SQLDAP

Ever wanted to query AD or LDAP with SQL like queries ?

I'm going to answer this question myself: yes !
Why ? Because I never could remember all the ldapsearch
arguments and filters, etc.

But after building this tool I am now a master of ldapsearch :)

## Supported queries:

  * simple select queries: `SELECT * FROM "$tablename" WHERE var=val;`
  * `show databases;` `show tables;`

## Work in Progress:

  * update queries: Don't use this in a production environment !!!


## Example queries:

`@group` should be defined in `sqldap.ini` (see `sqldap.ini.example`)

Select from default (first) configured server:
```bash
[user@awesome ~]$ sqldap 'SELECT memberuid FROM @group WHERE cn=groupname'
```

Select from a different configured Active Directory server named `examplead`
```bash
[user@awesome ~]$ sqldap 'SELECT gid FROM @group ' examplead
```

#### Don't use `>` and `<`
`>` and `<` are not supported, work your way around this problem by using: `>=` and `<=`


#### This is a valid query:
```bash
[user@awesome ~]$ sqldap 'SELECT uid,cn,passwordretrycount,ou FROM @people WHERE passwordretrycount>=3'
```

#### This is an invalid query:
```bash
[user@awesome ~]$ sqldap 'SELECT uid,cn,passwordretrycount,ou FROM @people WHERE passwordretrycount>2'`
```

#### You can also run queries that are defined in the `sqldap.ini` config file:
```bash
[user@awesome ~]$ sqldap @passwordretrycount
```

#### When you pass a filename as an argument, then sqldap parses the file and executes the queries that are defined this file

```bash
[user@awesome ~]$ sqldap queries.sql

Using config file /home/user/sqldap/sqldap.ini
Using server: exampleldap (ldap://ldap.example.com:389)

+-------+-------------+--------------------+----------+
| uid   | cn          | passwordretrycount | ou       |
+-------+-------------+--------------------+----------+
| user1 | Username1   | 3                  | group1   |
+-------+-------------+--------------------+----------+
| user2 | Username2   | 3                  | group2   |
+-------+-------------+--------------------+----------+
| user3 | Username3   | 3                  | group3   |
+-------+-------------+--------------------+----------+

[user@awesome ~]$

```

### Compiling from source
First you'll have to install Rust on your system:
```bash
[user@awesome ~]$ curl https://sh.rustup.rs -sSf | sh
```
Now run the following command in the root of the project: 

```bash
[user@awesome ~]$ cargo build --release
```

The ```sqldap``` binary can be found in the ```target/release/``` folder.
