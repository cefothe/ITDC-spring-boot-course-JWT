```
docker run --name internet-provider -e MYSQL_ROOT_PASSWORD=my-secret-pw -p 3306:3306 -d mysql
```

```
INSERT INTO roles(name) VALUES('ROLE_CUSTOMER');
INSERT INTO roles(name) VALUES('ROLE_ADMIN');
INSERT INTO roles(name) VALUES('ROLE_MODERATOR');
```

