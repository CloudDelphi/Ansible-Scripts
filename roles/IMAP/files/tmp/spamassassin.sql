-- Sources: https://svn.apache.org/repos/asf/spamassassin/trunk/sql/awl_mysql.sql
--          https://svn.apache.org/repos/asf/spamassassin/trunk/sql/bayes_mysql.sql

CREATE TABLE awl (
    username VARCHAR(100)   NOT NULL DEFAULT '',
    email    VARBINARY(255) NOT NULL DEFAULT '',
    ip       VARCHAR(40)    NOT NULL DEFAULT '',
    count    INT(11)        NOT NULL DEFAULT 0,
    totscore FLOAT          NOT NULL DEFAULT 0,
    signedby VARCHAR(255)   NOT NULL DEFAULT '',
    PRIMARY KEY (username,email,signedby,ip)
) ENGINE=InnoDB;

CREATE TABLE bayes_expire (
    id      INT(11) NOT NULL DEFAULT 0,
    runtime INT(11) NOT NULL DEFAULT 0,
    KEY bayes_expire_idx1 (id)
) ENGINE=InnoDB;

CREATE TABLE bayes_global_vars (
    variable VARCHAR(30)  NOT NULL default '',
    value    VARCHAR(200) NOT NULL default '',
    PRIMARY KEY (variable)
) ENGINE=InnoDB;
INSERT INTO bayes_global_vars VALUES ('VERSION','3');

CREATE TABLE bayes_seen (
    id    INT(11)             NOT NULL DEFAULT 0,
    msgid VARCHAR(200) BINARY NOT NULL DEFAULT '',
    flag  CHAR(1)             NOT NULL DEFAULT '',
    PRIMARY KEY (id,msgid)
) ENGINE=InnoDB;

CREATE TABLE bayes_token (
    id         INT(11)   NOT NULL DEFAULT 0,
    token      BINARY(5) NOT NULL DEFAULT '',
    spam_count INT(11)   NOT NULL DEFAULT 0,
    ham_count  INT(11)   NOT NULL DEFAULT 0,
    atime      INT(11)   NOT NULL DEFAULT 0,
    PRIMARY KEY (id, token),
    INDEX bayes_token_idx1 (id, atime)
) ENGINE=InnoDB;

CREATE TABLE bayes_vars (
    id                 INT(11)      NOT NULL AUTO_INCREMENT,
    username           VARCHAR(200) NOT NULL DEFAULT '',
    spam_count         INT(11)      NOT NULL DEFAULT 0,
    ham_count          INT(11)      NOT NULL DEFAULT 0,
    token_count        INT(11)      NOT NULL DEFAULT 0,
    last_expire        INT(11)      NOT NULL DEFAULT 0,
    last_atime_delta   INT(11)      NOT NULL DEFAULT 0,
    last_expire_reduce INT(11)      NOT NULL DEFAULT 0,
    oldest_token_age   INT(11)      NOT NULL DEFAULT 2147483647,
    newest_token_age   INT(11)      NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE bayes_vars_idx1 (username)
) ENGINE=InnoDB;
