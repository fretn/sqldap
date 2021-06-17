// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![warn(clippy::all)]

//use std::fs;

use simple_logger::SimpleLogger;
use sqlparser::ast::Expr;
use sqlparser::ast::Ident;
use sqlparser::ast::SelectItem;
use sqlparser::ast::SetExpr;
use sqlparser::ast::Statement;
use sqlparser::ast::TableFactor;
use sqlparser::dialect::*;
use sqlparser::parser::Parser;
//use sqlparser::ast::Expr::BinaryOp;

//use derive_more::Into;

use std::collections::HashMap;
use std::collections::HashSet;

use term_table::{
    row::Row,
    table_cell::{Alignment, TableCell},
};
use term_table::{Table, TableStyle};

use ini::Ini;

use anyhow::{bail, Context, Result};

use ldap3::Mod::Replace;
use ldap3::{LdapConn, Mod, Scope, SearchEntry, LdapConnSettings};

const USAGE: &str = r#"
Usage:
$ sqldap filename.sql [server]
or
$ sqldap "SELECT uid FROM dc=example,dc=com WHERE gid=100" [server]

When server is not provided then the first found server in sqldap.ini
will be used as server.
"#;

const CONFIG_FILE_EXAMPLE: &str = r#"
To create a config file, you can use the folling template

[dirserver1]
connection=ldap://ldap.example.com:389
binddn=uid=admin,ou=Admins,dc=example,dc=com
bindpassword=SECRETPASSWORD
[dirserver1.tables]
people=ou=people,dc=example,dc=com
group=ou=Group,dc=example,dc=com

[dirserver2]
connection=ldap://ad.example.com:389
"#;

fn parse_selection(selection: Expr) -> Result<String> {
    //println!("{:#?}", selection);
    let mut result_string = String::from("");

    match selection {
        Expr::BinaryOp { left, op, right } => {
            if op.to_string() == "OR" {
                result_string += "|";
            } else if op.to_string() == "AND" {
                result_string += "&";
            }
            match *left {
                Expr::Identifier(ident) => result_string = result_string + "(" + &ident.to_string(),
                Expr::Value(value) => result_string = result_string + "(" + &value.to_string(),
                Expr::Wildcard => {
                    result_string += "(*";
                }
                _ => result_string += &parse_selection(*left).context("Cannot parse selection")?,
            }
            if op.to_string() == "=" {
                result_string += &op.to_string();
            }
            if op.to_string() == ">=" {
                result_string += &op.to_string();
            }
            if op.to_string() == "<=" {
                result_string += &op.to_string();
            }
            match *right {
                Expr::Identifier(ident) => {
                    let val = ident
                        .to_string()
                        .trim_end_matches('\"')
                        .trim_start_matches('\"')
                        .to_string();
                    let val = val.replace("%", "*");
                    result_string = result_string + &val + ")";
                }
                Expr::Value(value) => {
                    //let val = value.to_string().trim_end_matches("\"").trim_start_matches("\"").to_string();
                    //let val = val.replace("%","*");
                    //result_string = result_string + &val.to_string() + ")";
                    result_string = result_string + &value.to_string() + ")";
                }
                Expr::Wildcard => {
                    result_string += "*)";
                }
                _ => result_string += &parse_selection(*right).context("Cannot parse selection")?,
            }
            //println!("BinaryOp right: {}", right);
        }
        Expr::Nested(expression) => {
            //println!("Detected Nested");
            result_string = "(".to_owned() + &result_string;
            result_string += &parse_selection(*expression).context("Cannot parse selection")?;
            result_string += ")";
        }
        _ => bail!("Non supported variant"),
    }

    Ok(result_string)
}

// TODO: UPDATE
// see: https://docs.rs/ldap3/0.8.1/ldap3/struct.Ldap.html#method.modifydn
// or: https://docs.rs/ldap3/0.8.1/ldap3/struct.Ldap.html#method.modify
#[derive(Clone, PartialEq)]
enum QueryType {
    SELECT = 0,
    SHOW = 1,
    UPDATE = 2,
}

struct SqldapQuery {
    qtype: QueryType,
    identifiers: Vec<String>,
    wildcard: bool,
    table: String,
    filter: String,
    var: String,
}

fn parse_query(
    dialect: Box<dyn Dialect>,
    sql: &str,
    tables: HashMap<String, String>,
    ldap: &mut LdapConn,
) -> Result<SqldapQuery> {
    let parse_result = Parser::parse_sql(&*dialect, &sql);
    let parse_result = parse_result.context("Cannot parse sql")?;

    let mut query: SqldapQuery = SqldapQuery {
        identifiers: Vec::new(),
        wildcard: false,
        table: String::from(""),
        filter: String::from(""),
        qtype: QueryType::SELECT,
        var: String::from(""),
    };

    for stmt in parse_result {
        //println!("{}", stmt);
        match stmt {
            Statement::Query(s) => {
                query.qtype = QueryType::SELECT;
                match s.body {
                    SetExpr::Select(s) => {
                        for expr in s.projection {
                            match expr {
                                SelectItem::UnnamedExpr(expr) => {
                                    match expr {
                                        Expr::Identifier(ident) => {
                                            query.identifiers.push(ident.to_string())
                                        } //println!("--> {}", ident),
                                        _ => bail!("Unsupported SelectItem::UnnamedExpr(expr)"),
                                    }
                                }
                                SelectItem::Wildcard => query.wildcard = true,
                                _ => bail!("Unsupported SelectItem"),
                            }
                        }
                        for table in s.from {
                            match table.relation {
                                TableFactor::Table {
                                    name,
                                    alias: _,
                                    args: _,
                                    with_hints: _,
                                } => {
                                    query.table = name.to_string();
                                    query.table = query
                                        .table
                                        .trim_end_matches('\"')
                                        .trim_start_matches('\"')
                                        .to_string();
                                    for (table, value) in &tables {
                                        query.table =
                                            query.table.replace(&format!("@{}", table), value);
                                    }
                                }
                                _ => bail!("Unsupported TableFactor"),
                            }
                        }
                        //println!("->{:#?}", s.selection);
                        let binary_op = if s.selection.is_some() {
                            let mut result = parse_selection(s.selection.unwrap())
                                .context("Cannot parse selection")?;
                            if !result.starts_with('(') {
                                result = format!("({})", result);
                            }
                            result
                        } else {
                            String::from("")
                        };
                        query.filter = binary_op;
                    }
                    _ => bail!("Unsupported Statement::Query(s)"),
                }
            }
            //Statement::Update { table_name: table_name, assignments: assignments, selection: selection } => {
            Statement::Update {
                table_name,
                assignments,
                selection,
            } => {
                query.qtype = QueryType::UPDATE;
                //println!("{:#?}", table_name);
                //println!("{:#?}", assignments);
                //println!("{:#?}", selection);
                //for table in table_name {
                match table_name {
                    sqlparser::ast::ObjectName(ident) => {
                        for i in ident {
                            match i {
                                Ident {
                                    value: val,
                                    quote_style: _,
                                } => {
                                    println!("table_name: {}", &val);
                                    //query.var = val;
                                    query.table = val;
                                }
                            }
                        }
                    }
                }
                let mut mod_vec = Vec::new();
                for assignment in assignments {
                    //println!("{:#?}", parse_selection(assignment.value));
                    //println!("{:#?} {:#?}", assignment.id, assignment.value);
                    //let mut var = String::from("");
                    let mut val = HashSet::new();
                    let var = match assignment.id {
                        Ident {
                            value: val,
                            quote_style: _,
                        } => {
                            query.identifiers.push(val.to_string());
                            //println!("SET: {}", val);
                            format!("{}", val)
                            //query.var = val;
                        }
                    };
                    let newval = match assignment.value {
                        Expr::Value(value) => {
                            value.to_string()
                            //let tmp = value.to_string().clone();
                            //println!("{}", &value);
                        }
                        Expr::Identifier(ident) => {
                            ident.to_string()
                            //let tmp = ident.to_string().clone();
                            //val.insert(tmp.as_str());
                            //println!("{}", &ident);
                        }
                        _ => bail!("Only Value and Identifier are supported."),
                    };
                    val.insert(format!("{}", newval));
                    mod_vec.push(Replace(format!("{}", &var), val));
                }
                query.identifiers.push("entrydn".to_string());
                //}
                //println!("->{:#?}", s.selection);
                // THIS SHOULD BE EMPTY
                // as ldap modify is not compatible with an sql where clause
                // the table_name should be the full dn
                // so where uid=username cannot be used, the table_name should be
                // uid=username,ou=group,ou=people,o=department,dc=example,dc=com

                // OR

                // the only way around this is first do a query for all entries
                // where uid=username or uidnumber>=10 or whatever (with a possible wildcard)
                // get the full dns for these entries, and then run ldap modify on all of
                // them through a loop

                let binary_op = if selection.is_some() {
                    let mut result =
                        parse_selection(selection.unwrap()).context("Cannot parse selection")?;
                    if !result.starts_with('(') {
                        result = format!("({})", result);
                    }
                    result
                } else {
                    String::from("")
                };
                //println!("->{:#?}", &binary_op);
                query.filter = binary_op;

                //println!("{:#?}", query.identifiers);
                let (rs, _res) = ldap
                    .search(
                        &query.table,
                        Scope::Subtree,
                        &query.filter,
                        query.identifiers.clone(),
                    )?
                    .success()
                    .context("Ldap search failed")?;

                //let mut result = Vec::new();
                //let mut key = String::from("");

                //let mut mod_vec_update = Vec::new();
                for entry in rs {
                    let mut got_error = false;
                    let se = SearchEntry::construct(entry);

                    let mut entrydn = String::from("");
                    for a in se.attrs {
                        let (key_attr, val_attr) = a;

                        if val_attr.len() > 1 {
                            println!("ERROR: attribute {} is an array, which cannot be modified. Please use delete or add.", &key_attr);
                            // REMARK: maybe we should get for example all memberOf values, store them in a Vec, update
                            // the value we want to update and send this in the Replace mod
                            /*
                            for i in mod_vec.iter() {
                                match i {
                                    Mod::Replace(key, val) => {
                                        if key == &key_attr {
                                            println!("key: {}", key);
                                            mod_vec_update.push(Replace(format!("{}", &key), val));
                                        } else {
                                            mod_vec_update.push(Replace(format!("{}", &key), val));
                                        }
                                    }
                                    _ => println!("hoi"),
                                }
                            }
                            */
                            got_error = true;
                        } else {
                            if key_attr == "entrydn" {
                                entrydn = val_attr[0].clone();
                                //println!("{} -> {:?} ", &val_attr[0], mod_vec);
                                /*

                                let res = ldap
                                        .with_controls(RelaxRules.critical())
                                        .modify("uid=inejge,ou=People,dc=example,dc=org", mod_vec)?
                                        .success()?;

                                                            */
                            }
                        }
                    }
                    if !got_error {
                        println!("updating: {} -> {:?} ", &entrydn, mod_vec);
                        println!("---------------");
                    } else {
                        println!("{} will not be updated ", &entrydn);
                    }
                }

                //println!("{:#?}", result);
            }
            Statement::ShowVariable { variable: var } => {
                query.qtype = QueryType::SHOW;
                //println!("{:?}", var);
                match var {
                    Ident {
                        value: val,
                        quote_style: _,
                    } => {
                        //println!("{}", val);
                        query.var = val;
                    }
                }
            }
            _ => bail!("Only SELECT AND UPDATE (work in progress) queries are supported."),
        }
    }

    //if query.filter.is_empty() && query.qtype.clone() == QueryType::SELECT {
    if query.filter.is_empty() && query.qtype == QueryType::SELECT {
        query.filter = "(objectClass=*)".to_string();
        println!("'WHERE attr=val' was not supplied, added (objectClass=*) as search filter.\n");
    }

    Ok(query)
}

fn get_config_cwd(filename: &str) -> Option<String> {
    let cwd = match std::env::current_dir() {
        Ok(path) => Some(path.display().to_string()),
        Err(_e) => None,
    };

    if cwd.is_some() {
        return Some(format!("{}/{}", cwd.unwrap(), filename));
    }

    None
}

fn get_config_home(filename: &str) -> Option<String> {
    let home = match home::home_dir() {
        Some(path) => Some(path.display().to_string()),
        None => None,
    };

    if home.is_some() {
        return Some(format!("{}/.{}", home.unwrap(), filename));
    }

    None
}

fn get_config_etc(filename: &str) -> Option<String> {
    if std::path::Path::new("/etc/").exists() {
        return Some(format!("/etc/{}", filename));
    }

    None
}

fn get_config_usage(filename: &str) -> Result<String> {
    let mut config_usage = vec![
        "".to_string(),
        "".to_string(),
        "sqldap searches for a config file in the following locations,".to_string(),
        "in the folling order:".to_string(),
        "".to_string(),
    ];

    let cwd = get_config_cwd(filename);
    if let Some(cwd_config) = cwd {
        config_usage.push(format!(" - {}", cwd_config));
    }

    let home = get_config_home(filename);
    if let Some(home_config) = home {
        config_usage.push(format!(" - {}", home_config));
    }

    let etc = get_config_etc(filename);
    if let Some(etc_config) = etc {
        config_usage.push(format!(" - {}", etc_config));
    }

    /*
        let config_file_example = r#"
    To create a config file, you can use the folling template

    [dirserver1]
    connection=ldap://ldap.example.com:389
    binddn=uid=admin,ou=Admins,dc=example,dc=com
    bindpassword=SECRETPASSWORD
    [dirserver1.tables]
    people=ou=people,dc=example,dc=com
    group=ou=Group,dc=example,dc=com

    [dirserver2]
    connection=ldap://ad.example.com:389
        "#;
        */

    config_usage.push(CONFIG_FILE_EXAMPLE.to_string());

    Ok(config_usage.join("\n"))
}

fn load_config(filename: &str) -> Result<Ini> {
    let cwd = get_config_cwd(filename);
    if let Some(cwd_config) = cwd {
        let conf = Ini::load_from_file(&cwd_config);
        if let Ok(config) = conf {
            println!("Using config file {}", cwd_config);
            return Ok(config);
        }
    }

    let home = get_config_home(filename);
    if let Some(home_config) = home {
        let conf = Ini::load_from_file(&home_config);
        if let Ok(config) = conf {
            println!("Using config file {}", home_config);
            return Ok(config);
        }
    }

    let etc = get_config_home(filename);
    if let Some(etc_config) = etc {
        let conf = Ini::load_from_file(&etc_config);
        if let Ok(config) = conf {
            println!("Using config file {}", etc_config);
            return Ok(config);
        }
    }

    bail!("Couldn't find the required config file.")
}

fn fits_on_screen(table_data: &str) -> bool {
    if let Some(table_width) = table_data.find('\n') {
        if let Some((w, _h)) = term_size::dimensions() {
            if table_width > w {
                return false;
            }
        }
    }
    true
}

fn main() -> Result<()> {
    SimpleLogger::new()
        .with_level(ldap3::log::LevelFilter::Error)
        .init()
        .unwrap();

    let filename = "sqldap.ini";
    let conf =
        load_config(filename).context(get_config_usage(filename).context("Cannot get usage")?)?;

    // now parse command line args
    // first arg should be the name of the section in the config file
    let tmpsql = match std::env::args().nth(1) {
        //.context(USAGE)?;
        Some(sql) => sql,
        None => {
            println!("{}", USAGE);
            std::process::exit(0);
        }
    };
    let mut servername = match std::env::args().nth(2) {
        Some(n) => n,
        None => String::from(""),
    }; //.context(USAGE)?;

    // if we have received an sql file instead of a direct query
    // read the file
    let sql = if std::path::Path::new(&tmpsql).exists() {
        std::fs::read_to_string(&tmpsql).context("Cannot read sql file")?
    } else {
        tmpsql
    };

    // if sql starts with @
    // then the query is configured in
    // sqldap.ini
    // eg:
    /*
        [testldap]
        connection=ldap://ldap.domain.com:389
        binddn=uid=administrator,ou=Admins,ou=domain,dc=com
        bindpassword=DIFFIculT
        [testldap.tables]
        people=ou=people,o=department,dc=domain,dc=be
        group=ou=Group,o=department,dc=domain,dc=be
        [testldap.queries]
        passwordretrycount=SELECT uid FROM @people WHERE passwordretrycount>=3
    */

    let sql = sql.replace(";\n", ";");
    let mut sql = sql.split(';').collect::<Vec<&str>>();

    // search for queries starting with '@'
    let mut found_at = false;
    for tmp in sql.iter() {
        if tmp.starts_with('@') {
            found_at = true;
        }
    }

    let mut connection = None;
    let mut binddn = None;
    let mut bindpassword = None;
    let mut tables = HashMap::new();

    for (sec, prop) in &conf {
        if servername.is_empty() && sec.is_some() {
            servername = sec.unwrap().to_string();
        }
        if sec.is_some() && servername == sec.unwrap() {
            for (key, value) in prop.iter() {
                if key == "connection" {
                    connection = Some(value)
                }
                if key == "binddn" {
                    binddn = Some(value)
                }
                if key == "bindpassword" {
                    bindpassword = Some(value)
                }
            }
        }
        if sec.is_some() && format!("{}.tables", servername) == sec.unwrap() {
            for (key, value) in prop.iter() {
                tables.insert(key.to_string(), value.to_string());
            }
        }

        // replace @somequery with the preconfigured query from sqldap.ini
        if found_at && sec.is_some() && format!("{}.queries", servername) == sec.unwrap() {
            for (key, value) in prop.iter() {
                for query in sql.iter_mut() {
                    if *query == format!("@{}", key) {
                        *query = value;
                    }
                }
            }
        }
    }

    let connection = connection.context(format!(
        "Key 'connection' in section {} could not be found.",
        servername
    ))?;

    println!("Using server: {} ({})\n", servername, connection);
    for sqlquery in sql.iter() {
        if sqlquery.is_empty() || sqlquery == &"\n" {
            continue;
        }
        let dialect = Box::new(GenericDialect {});
        /*
        let dialect: Box<dyn Dialect> = match std::env::args().nth(3).unwrap_or_default().as_ref() {
            "--ansi" => Box::new(AnsiDialect {}),
            "--postgres" => Box::new(PostgreSqlDialect {}),
            "--ms" => Box::new(MsSqlDialect {}),
            "--generic" | "" => Box::new(GenericDialect {}),
            s => panic!("Unexpected parameter: {}", s),
        };
        */
        //let query =
        //   parse_query(dialect, &sqlquery, tables.clone()).context("Query is not supported")?;

        //let mut ldap = LdapConn::new(connection).context("Cannot connect to LDAP")?;
        let mut ldap = LdapConn::with_settings(LdapConnSettings::new().set_no_tls_verify(true),connection).context("Cannot connect to LDAP")?;
        if binddn.is_some() && bindpassword.is_some() {
            let _res = ldap
                .simple_bind(binddn.unwrap(), bindpassword.unwrap())?
                .success()
                .context("ldap simple_bind failed")?;
        }

        let query = parse_query(dialect, &sqlquery, tables.clone(), &mut ldap)
            .context("Query is not supported")?;

        if query.qtype == QueryType::SHOW {
            if query.var.to_uppercase() == "TABLES" {
                if !tables.is_empty() {
                    let mut table = Table::new();
                    table.style = TableStyle::simple();
                    let mut row = Vec::new();
                    row.push(TableCell::new_with_alignment(
                        "Table name",
                        1,
                        Alignment::Left,
                    ));
                    row.push(TableCell::new_with_alignment(
                        "Configured dn",
                        1,
                        Alignment::Left,
                    ));
                    table.add_row(Row::new(row));

                    for (key, value) in &tables {
                        //println!("{} ({})", table, value);
                        let mut row = Vec::new();
                        row.push(TableCell::new_with_alignment(key, 1, Alignment::Left));
                        row.push(TableCell::new_with_alignment(value, 1, Alignment::Left));
                        table.add_row(Row::new(row));
                    }
                    if sql.len() > 1 {
                        println!("Results for query '{}': \n", sqlquery);
                    }
                    println!("{}", table.render());
                } else {
                    println!("No tables are configured in your config file.");
                    println!("See example config file below.\n");
                    println!("{}", CONFIG_FILE_EXAMPLE);
                }
            } else if query.var.to_uppercase() == "DATABASES" {
                let mut table = Table::new();
                table.style = TableStyle::simple();
                let mut row = Vec::new();
                row.push(TableCell::new_with_alignment(
                    "Database name",
                    1,
                    Alignment::Left,
                ));
                row.push(TableCell::new_with_alignment(
                    "Configured server",
                    1,
                    Alignment::Left,
                ));
                table.add_row(Row::new(row));

                for (sec, prop) in &conf {
                    if sec.is_some()
                        && sec.unwrap().find(".tables").is_none()
                        && sec.unwrap().find(".queries").is_none()
                    {
                        let mut row = Vec::new();
                        row.push(TableCell::new_with_alignment(
                            sec.unwrap(),
                            1,
                            Alignment::Left,
                        ));
                        for (key, value) in prop.iter() {
                            if key == "connection" {
                                row.push(TableCell::new_with_alignment(value, 1, Alignment::Left));
                            }
                        }
                        table.add_row(Row::new(row));
                        //println!("{:?}", prop);
                    }
                }
                if sql.len() > 1 {
                    println!("Results for query '{}': \n", sqlquery);
                }
                println!("{}", table.render());
            }
        } else if query.qtype == QueryType::SELECT {
            let (rs, _res) = ldap
                .search(
                    &query.table,
                    Scope::Subtree,
                    &query.filter,
                    query.identifiers.clone(),
                )?
                .success()
                .context("Ldap search failed")?;

            let identifier_len = query.identifiers.len() as usize;
            let one_table = identifier_len == 1;

            if sql.len() > 1 {
                println!("Results for query '{}': \n", sqlquery);
            }

            // if we requested only one field, only show one table
            let result = if !one_table || query.wildcard {
                let mut result = Vec::new();
                for entry in rs {
                    let se = SearchEntry::construct(entry);

                    let mut keyval = HashMap::new();
                    for a in se.attrs {
                        let (key, value) = a;
                        keyval.insert(key, value.join("\n"));
                    }
                    result.push(keyval);
                }
                result
            } else {
                let mut result = Vec::new();
                let mut key = String::from("");
                for entry in rs {
                    let se = SearchEntry::construct(entry);

                    for a in se.attrs {
                        let (key_attr, val_attr) = a;
                        key = key_attr;
                        result.push(val_attr.join("\n"));
                    }
                }
                let mut keyval = HashMap::new();
                keyval.insert(key, result.join("\n"));
                let mut result = Vec::new();
                result.push(keyval);

                result
            };

            if binddn.is_some() && bindpassword.is_some() {
                ldap.unbind().context("ldap unbind failed")?;
            }

            // the reason we stored everything in a vec is because
            // ldap3 doesn't return the requested fields in the same
            // order they where requested, eg: cn,uid,passwordretrycount
            // every new run they are resulted in a different order
            // this fixes this problem

            let mut table = Table::new();
            table.style = TableStyle::simple();

            if !query.wildcard {
                let mut row = Vec::new();

                // print header
                for key in &query.identifiers {
                    row.push(TableCell::new_with_alignment(key, 1, Alignment::Left));
                }
                if !row.is_empty() {
                    table.add_row(Row::new(row));
                }

                // print data
                for result_entry in result.iter() {
                    let mut row = Vec::new();

                    for key in &query.identifiers {
                        let val = result_entry.get(key);
                        if let Some(value) = val {
                            row.push(TableCell::new_with_alignment(value, 1, Alignment::Left));
                        } else {
                            row.push(TableCell::new_with_alignment("", 1, Alignment::Left));
                        }
                    }
                    if !row.is_empty() {
                        table.add_row(Row::new(row));
                    }
                }

                let table_data = table.render();

                if !fits_on_screen(&table_data) {
                    for result_entry in result.iter() {
                        if !one_table {
                            table = Table::new();
                            table.style = TableStyle::simple();
                        }
                        for key in &query.identifiers {
                            let val = result_entry.get(&key.to_string());
                            if let Some(value) = val {
                                let mut row = Vec::new();
                                row.push(TableCell::new_with_alignment(key, 1, Alignment::Left));
                                row.push(TableCell::new_with_alignment(value, 1, Alignment::Left));
                                table.add_row(Row::new(row));
                            }
                        }
                        if !one_table {
                            if !table.rows.is_empty() {
                                println!("{}", table.render());
                            } else {
                                println!("Nothing found.");
                            }
                        }
                    }
                    if one_table {
                        if !table.rows.is_empty() {
                            println!("{}", table.render());
                        } else {
                            println!("Nothing found.");
                        }
                    }
                } else {
                    if !table.rows.is_empty() {
                        println!("{}", table_data);
                    } else {
                        println!("Nothing found.");
                    }
                }
            } else {
                let mut keys = Vec::new();

                for result_entry in result.iter() {
                    //for (key, _val) in result_entry {
                    for key in result_entry.keys() {
                        keys.push(key.to_string());
                    }
                }

                keys.sort(); // sort the rows
                keys.dedup(); // remove duplicates

                let mut row = Vec::new();
                for key in keys.iter() {
                    row.push(TableCell::new_with_alignment(key, 1, Alignment::Left));
                }
                if !row.is_empty() {
                    table.add_row(Row::new(row));
                }

                for result_entry in result.iter() {
                    let mut row = Vec::new();
                    for key in keys.iter() {
                        let val = result_entry.get(&key.to_string());
                        if let Some(value) = val {
                            row.push(TableCell::new_with_alignment(value, 1, Alignment::Left));
                        } else {
                            row.push(TableCell::new_with_alignment("", 1, Alignment::Left));
                        }
                    }
                    if !row.is_empty() {
                        table.add_row(Row::new(row));
                    }
                }

                let table_data = table.render();

                if !fits_on_screen(&table_data) {
                    for result_entry in result {
                        if !one_table {
                            table = Table::new();
                            table.style = TableStyle::simple();
                        }
                        for key in keys.iter() {
                            let val = result_entry.get(&key.to_string());
                            if let Some(value) = val {
                                let mut row = Vec::new();
                                row.push(TableCell::new_with_alignment(key, 1, Alignment::Left));
                                row.push(TableCell::new_with_alignment(value, 1, Alignment::Left));
                                table.add_row(Row::new(row));
                            }
                        }
                        if !one_table {
                            if !table.rows.is_empty() {
                                println!("{}", table.render());
                                println!("\nConsider replacing * with a subset of the folling fields: \n");
                                println!("{}", keys.join(","));
                            } else {
                                println!("Nothing found.");
                            }
                        }
                    }
                    if one_table {
                        if !table.rows.is_empty() {
                            println!("{}", table.render());
                            println!(
                                "\nConsider replacing * with a subset of the folling fields: \n"
                            );
                            println!("{}", keys.join(","));
                        } else {
                            println!("Nothing found.");
                        }
                    }
                } else {
                    if !table.rows.is_empty() {
                        println!("{}", table_data);
                    } else {
                        println!("Nothing found.");
                    }
                }
            }
        }
    }
    Ok(())
}
