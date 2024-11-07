
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions =[
    {
        "question": "Sarah is tasked with testing a web application that uses user input to construct SQL queries directly. She notices the application fails to properly sanitize input. By inputting a specific string, she gains access to unauthorized data. What type of SQL Injection is Sarah likely exploiting?",
        "options": [
            "Blind SQL Injection",
            "Union-based SQL Injection",
            "Error-based SQL Injection",
            "In-band SQL Injection"
        ],
        "answer": "In-band SQL Injection"
    },
    {
        "question": "During a penetration test, John uses a SQL injection payload to extract data from a database. He notices that the application only returns results after a delay. Which type of SQL injection is he encountering?",
        "options": [
            "Time-based Blind SQL Injection",
            "Boolean-based Blind SQL Injection",
            "Union-based SQL Injection",
            "Error-based SQL Injection"
        ],
        "answer": "Time-based Blind SQL Injection"
    },
    {
        "question": "A developer is implementing input validation to prevent SQL injection but is unsure which method is most effective. Which of the following techniques is best for mitigating SQL injection risks?",
        "options": [
            "Using stored procedures with parameterized queries",
            "Sanitizing user input with regex",
            "Encoding all output data",
            "Using ORM frameworks without further validation"
        ],
        "answer": "Using stored procedures with parameterized queries"
    },
    {
        "question": "While testing an application, you realize that injecting a single quote (') does not yield an error but results in no output. What might indicate about the application's response?",
        "options": [
            "The application is vulnerable to Boolean-based SQL injection.",
            "The application is secure against SQL injection.",
            "The application uses prepared statements.",
            "The database has been configured to prevent SQL injection."
        ],
        "answer": "The application is vulnerable to Boolean-based SQL injection."
    },
    {
        "question": "Max discovers that the application allows him to inject a UNION SELECT statement. After several attempts, he successfully retrieves sensitive user information. What SQL Injection type did Max exploit?",
        "options": [
            "Union-based SQL Injection",
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "In-band SQL Injection"
        ],
        "answer": "Union-based SQL Injection"
    },
    {
        "question": "Emma notices that the web application’s database error messages reveal the structure of the database. She exploits this by crafting specific queries. Which attack type is she leveraging?",
        "options": [
            "Error-based SQL Injection",
            "Blind SQL Injection",
            "Time-based SQL Injection",
            "Union-based SQL Injection"
        ],
        "answer": "Error-based SQL Injection"
    },
    {
        "question": "A security analyst is reviewing an application that concatenates user input directly into SQL queries. Which of the following would be the most effective countermeasure against SQL injection?",
        "options": [
            "Implement input validation and use parameterized queries.",
            "Use a web application firewall.",
            "Obfuscate SQL queries.",
            "Regularly update the database software."
        ],
        "answer": "Implement input validation and use parameterized queries."
    },
    {
        "question": "During a SQL injection test, you attempt to extract data using a 'SELECT * FROM users WHERE id = 1 OR 1=1'. What does the 'OR 1=1' condition do in this context?",
        "options": [
            "It restricts the query to a single user.",
            "It bypasses authentication checks.",
            "It always evaluates to true, returning all records.",
            "It triggers an error in the SQL syntax."
        ],
        "answer": "It always evaluates to true, returning all records."
    },
    {
        "question": "An application uses dynamic SQL queries and provides detailed error messages. What type of SQL injection risk does this pose?",
        "options": [
            "Increased exposure to parameterized query vulnerabilities.",
            "Easier exploitation through error-based SQL injection.",
            "No significant risk if the application is updated regularly.",
            "Less risk since the application validates input."
        ],
        "answer": "Easier exploitation through error-based SQL injection."
    },
    {
        "question": "Which of the following tools is commonly used to automate SQL injection attacks?",
        "options": [
            "Nmap",
            "Burp Suite",
            "Wireshark",
            "Metasploit"
        ],
        "answer": "Burp Suite"
    },
    {
        "question": "A tester finds that when she injects a SQL payload, the application returns different data based on the timing of her requests. Which type of SQL injection is she dealing with?",
        "options": [
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "Time-based Blind SQL Injection",
            "Union-based SQL Injection"
        ],
        "answer": "Time-based Blind SQL Injection"
    },
    {
        "question": "What is the primary goal of an attacker when performing a SQL injection attack?",
        "options": [
            "To modify application source code.",
            "To gain unauthorized access to the database.",
            "To disrupt the web server.",
            "To encrypt data stored in the database."
        ],
        "answer": "To gain unauthorized access to the database."
    },
    {
        "question": "A company implements WAF (Web Application Firewall) to protect against SQL injection. What is the primary limitation of this approach?",
        "options": [
            "It cannot block all SQL injection attempts.",
            "It is expensive to maintain.",
            "It slows down application performance significantly.",
            "It requires constant updates to rules."
        ],
        "answer": "It cannot block all SQL injection attempts."
    },
    {
        "question": "What type of SQL injection technique involves injecting queries that exploit a lack of input validation to extract sensitive information without triggering errors?",
        "options": [
            "Blind SQL Injection",
            "In-band SQL Injection",
            "Error-based SQL Injection",
            "Union-based SQL Injection"
        ],
        "answer": "Blind SQL Injection"
    },
    {
        "question": "In a SQL injection attack, the attacker modifies the original query to include additional SQL commands. What is this process called?",
        "options": [
            "Query manipulation",
            "Command injection",
            "SQL execution",
            "Payload injection"
        ],
        "answer": "Query manipulation"
    },
    {
        "question": "Which of the following SQL injection techniques is used to bypass login forms by always returning true for authentication?",
        "options": [
            "Error-based SQL Injection",
            "Union-based SQL Injection",
            "Blind SQL Injection",
            "Time-based SQL Injection"
        ],
        "answer": "Blind SQL Injection"
    },
    {
        "question": "When using tools like SQLMap, what feature allows the user to specify which SQL injection techniques to test?",
        "options": [
            "Injection techniques",
            "Parameter testing",
            "Attack modes",
            "Payload selection"
        ],
        "answer": "Injection techniques"
    },
    {
        "question": "After successfully executing an SQL injection attack, what is the next step an attacker typically takes?",
        "options": [
            "Cover their tracks",
            "Execute denial-of-service commands",
            "Immediately disclose vulnerabilities",
            "Encrypt all data in the database"
        ],
        "answer": "Cover their tracks"
    },
    {
        "question": "An attacker injects the payload '1; DROP TABLE users;' into a web application. What is the outcome of this action if the query is executed?",
        "options": [
            "The user record is modified.",
            "The entire 'users' table is deleted.",
            "The attack fails silently.",
            "The application displays an error message."
        ],
        "answer": "The entire 'users' table is deleted."
    },
    {
        "question": "Which database function can be used to test for SQL injection vulnerabilities by checking how the application responds to crafted SQL queries?",
        "options": [
            "Transaction management",
            "Error handling",
            "Query logging",
            "Data encryption"
        ],
        "answer": "Error handling"
    },
    {
        "question": "In the context of SQL injection, what does the term 'payload' refer to?",
        "options": [
            "The malicious SQL code used in the attack.",
            "The web application firewall rules.",
            "The data returned from the database.",
            "The method of input validation."
        ],
        "answer": "The malicious SQL code used in the attack."
    },
    {
        "question": "A web application allows users to search for products using input fields that are not validated. An attacker uses this to input a SQL command. What is this an example of?",
        "options": [
            "Stored XSS",
            "SQL Injection",
            "CSRF",
            "Command Injection"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "What is one of the most common vulnerabilities that lead to SQL injection?",
        "options": [
            "Improper error handling",
            "Use of outdated libraries",
            "Weak passwords",
            "Poor encryption practices"
        ],
        "answer": "Improper error handling"
    },
    {
        "question": "If an application responds with 'SQL syntax error' when an attacker submits a payload, what does this indicate?",
        "options": [
            "The application is vulnerable to SQL injection.",
            "The attack was unsuccessful.",
            "The application uses parameterized queries.",
            "The database is properly secured."
        ],
        "answer": "The attack was unsuccessful."
    },
    {
        "question": "In a SQL injection attack, what is the purpose of using comments (e.g., -- or /*) in the payload?",
        "options": [
            "To confuse the database.",
            "To hide the rest of the SQL statement.",
            "To increase execution time.",
            "To return error messages."
        ],
        "answer": "To hide the rest of the SQL statement."
    },
    {
        "question": "During a penetration test, you discover that the application supports input like '1 OR 1=1'. What kind of risk does this represent?",
        "options": [
            "XSS vulnerability",
            "Blind SQL injection",
            "Insecure data storage",
            "SQL injection vulnerability"
        ],
        "answer": "SQL injection vulnerability"
    },
    {
        "question": "Which of the following is a countermeasure to prevent SQL injection attacks?",
        "options": [
            "Regularly changing database passwords",
            "Using prepared statements",
            "Encrypting all data in the database",
            "Obfuscating source code"
        ],
        "answer": "Using prepared statements"
    },
    {
        "question": "An application uses a GET method to send SQL queries based on user input. An attacker tries to modify the query through URL parameters. This illustrates what type of attack?",
        "options": [
            "Session hijacking",
            "SQL Injection",
            "Cross-site Scripting",
            "Command Injection"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "Which SQL function can be used to check for the existence of a user in a database while testing for SQL injection?",
        "options": [
            "SELECT COUNT(*)",
            "SHOW TABLES",
            "INSERT INTO",
            "DROP DATABASE"
        ],
        "answer": "SELECT COUNT(*)"
    },
    {
        "question": "An attacker uses the payload '1; WAITFOR DELAY '00:00:10'' to test for SQL injection vulnerabilities. What is the purpose of this payload?",
        "options": [
            "To bypass login forms.",
            "To extract database information.",
            "To test for time-based SQL injection.",
            "To delete data from the database."
        ],
        "answer": "To test for time-based SQL injection."
    },
    {
        "question": "A web application fails to validate input from a form that updates user profiles. An attacker submits a SQL payload to retrieve sensitive information. This is an example of which SQL injection type?",
        "options": [
            "In-band SQL Injection",
            "Stored SQL Injection",
            "Blind SQL Injection",
            "Time-based SQL Injection"
        ],
        "answer": "In-band SQL Injection"
    },
    {
        "question": "When an attacker uses SQL injection to execute arbitrary SQL commands against a database, what is this process called?",
        "options": [
            "Command execution",
            "Database exploitation",
            "SQL command injection",
            "Query manipulation"
        ],
        "answer": "SQL command injection"
    },
    {
        "question": "An application returns different results based on whether a user exists in the database. An attacker can exploit this to determine valid usernames. What type of SQL injection does this represent?",
        "options": [
            "Error-based SQL Injection",
            "Boolean-based Blind SQL Injection",
            "Time-based Blind SQL Injection",
            "In-band SQL Injection"
        ],
        "answer": "Boolean-based Blind SQL Injection"
    },
    {
        "question": "When a web application outputs SQL errors to the user, which security principle is being violated?",
        "options": [
            "Principle of least privilege",
            "Defense in depth",
            "Fail securely",
            "Security through obscurity"
        ],
        "answer": "Fail securely"
    },
    {
        "question": "During a test, an attacker tries multiple variations of a SQL injection payload to see which one successfully retrieves data. This technique is known as what?",
        "options": [
            "Fuzzing",
            "Brute forcing",
            "Enumeration",
            "Payload testing"
        ],
        "answer": "Fuzzing"
    },
    {
        "question": "What does the acronym 'WAF' stand for in the context of web security?",
        "options": [
            "Web Application Framework",
            "Web Application Firewall",
            "Web Application Functionality",
            "Web Access Filter"
        ],
        "answer": "Web Application Firewall"
    },
    {
        "question": "Which of the following best describes a 'second-order SQL injection'?",
        "options": [
            "Exploiting the database to inject malicious data.",
            "Injecting SQL code that affects the application later.",
            "Using SQL injection to bypass authentication.",
            "Querying the database using multiple injections."
        ],
        "answer": "Injecting SQL code that affects the application later."
    },
    {
        "question": "An attacker is using SQL injection to extract data from a database. Which response indicates the database is likely misconfigured?",
        "options": [
            "The application returns 'Data not found'.",
            "The application shows detailed SQL error messages.",
            "The application provides no response.",
            "The application only returns metadata."
        ],
        "answer": "The application shows detailed SQL error messages."
    },
    {
        "question": "Which of the following techniques would most likely help protect against SQL injection in a web application?",
        "options": [
            "Client-side input validation",
            "Use of stored procedures",
            "User education",
            "Regular password updates"
        ],
        "answer": "Use of stored procedures"
    },
    {
        "question": "During an SQL injection attack, what is the primary purpose of using a payload that terminates the current query and starts a new one?",
        "options": [
            "To increase the payload size.",
            "To execute multiple commands in one query.",
            "To bypass application security measures.",
            "To retrieve all database records."
        ],
        "answer": "To execute multiple commands in one query."
    },
    {
        "question": "An attacker inserts a comment symbol in a SQL injection attack to disable the rest of the query. What is the purpose of this action?",
        "options": [
            "To increase execution time.",
            "To hide error messages.",
            "To ensure the original query executes as intended.",
            "To bypass syntax validation."
        ],
        "answer": "To bypass syntax validation."
    },
    {
        "question": "Which SQL clause is often used in SQL injection to combine results from multiple SELECT statements?",
        "options": [
            "GROUP BY",
            "JOIN",
            "UNION",
            "ORDER BY"
        ],
        "answer": "UNION"
    },
    {
        "question": "What can an attacker achieve by exploiting an SQL injection vulnerability in a web application?",
        "options": [
            "Gain access to sensitive information.",
            "Modify application code.",
            "DDoS the server.",
            "Change the application's frontend."
        ],
        "answer": "Gain access to sensitive information."
    },
    {
        "question": "When attempting a SQL injection attack, what is the significance of the keyword 'AND' in the payload?",
        "options": [
            "It increases the complexity of the SQL statement.",
            "It combines conditions to manipulate query results.",
            "It terminates the current query.",
            "It prevents SQL errors."
        ],
        "answer": "It combines conditions to manipulate query results."
    },
    {
        "question": "What is a common mistake developers make that can lead to SQL injection vulnerabilities?",
        "options": [
            "Using prepared statements",
            "Validating user input",
            "Concatenating user input directly into SQL queries",
            "Implementing proper error handling"
        ],
        "answer": "Concatenating user input directly into SQL queries"
    },
    {
        "question": "If a web application allows file uploads and the attacker injects a payload that executes SQL commands through the uploaded file, what type of SQL injection is being used?",
        "options": [
            "File-based SQL Injection",
            "Stored SQL Injection",
            "Blind SQL Injection",
            "In-band SQL Injection"
        ],
        "answer": "File-based SQL Injection"
    },
    {
        "question": "When testing for SQL injection, what does the presence of error messages like 'SQL syntax error' indicate?",
        "options": [
            "The database is secure.",
            "The application is vulnerable.",
            "The attack is successful.",
            "The input validation is effective."
        ],
        "answer": "The application is vulnerable."
    },
    {
        "question": "During a penetration test, you find that an application returns the number of users in the database when the SQL injection is successful. What type of SQL injection is this?",
        "options": [
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "In-band SQL Injection",
            "Time-based SQL Injection"
        ],
        "answer": "In-band SQL Injection"
    },
    {
        "question": "Which of the following is a key characteristic of a blind SQL injection attack?",
        "options": [
            "The attacker receives detailed error messages.",
            "The attacker cannot see the output of their queries.",
            "The attacker can use UNION SELECT to retrieve data.",
            "The attacker exploits SQL errors directly."
        ],
        "answer": "The attacker cannot see the output of their queries."
    },
    {
        "question": "Which database management system is known for being particularly susceptible to SQL injection attacks due to its lack of default input validation?",
        "options": [
            "PostgreSQL",
            "MySQL",
            "Oracle",
            "Microsoft SQL Server"
        ],
        "answer": "MySQL"
    },
    {
        "question": "In the context of SQL injection, what does the term 'parameterized queries' refer to?",
        "options": [
            "Queries that use variable parameters for execution.",
            "Queries that are executed without any parameters.",
            "Queries that are vulnerable to SQL injection.",
            "Queries that dynamically generate SQL statements."
        ],
        "answer": "Queries that use variable parameters for execution."
    },
    {
        "question": "A web application’s search feature is vulnerable to SQL injection. What would be the best practice to secure it?",
        "options": [
            "Use client-side validation.",
            "Implement server-side input validation and parameterized queries.",
            "Sanitize user input using JavaScript.",
            "Only allow numeric input."
        ],
        "answer": "Implement server-side input validation and parameterized queries."
    },
    {
        "question": "If an attacker can perform SQL injection to execute commands like 'CREATE USER', what is the potential risk?",
        "options": [
            "Compromising user credentials.",
            "Modifying web application code.",
            "Altering network configurations.",
            "Accessing sensitive user data."
        ],
        "answer": "Compromising user credentials."
    },
    {
        "question": "What type of SQL injection can allow attackers to modify the data in a database without being detected?",
        "options": [
            "Stored SQL Injection",
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "Time-based SQL Injection"
        ],
        "answer": "Stored SQL Injection"
    },
    {
        "question": "An attacker exploits an SQL injection vulnerability to retrieve hashed passwords from a database. What technique might they use?",
        "options": [
            "UNION SELECT",
            "Stored procedures",
            "Data encryption",
            "Input validation"
        ],
        "answer": "UNION SELECT"
    },
    {
        "question": "When evaluating an application for SQL injection vulnerabilities, what is the significance of the HTTP response time when a payload is injected?",
        "options": [
            "It indicates whether the application is secure.",
            "It reveals the server's load.",
            "It can suggest whether the injection is successful.",
            "It shows the database's configuration."
        ],
        "answer": "It can suggest whether the injection is successful."
    },
    {
        "question": "In a SQL injection attack, what does the term 'stacked queries' refer to?",
        "options": [
            "Executing multiple SQL statements in one request.",
            "Storing multiple queries in the database.",
            "Combining results from different databases.",
            "Logging multiple attacks."
        ],
        "answer": "Executing multiple SQL statements in one request."
    },
    {
        "question": "Which SQL injection type typically relies on sending queries that do not return errors or results, but instead relies on the application's response time?",
        "options": [
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "In-band SQL Injection",
            "Union-based SQL Injection"
        ],
        "answer": "Blind SQL Injection"
    },
    {
        "question": "A penetration tester discovers that the application allows executing arbitrary commands through SQL injection. What is the most likely outcome?",
        "options": [
            "Access to sensitive information.",
            "Alteration of application behavior.",
            "Denial of service.",
            "All of the above."
        ],
        "answer": "All of the above."
    },
    {
        "question": "What is the primary function of SQLMap in the context of SQL injection testing?",
        "options": [
            "To provide detailed documentation.",
            "To automate the detection and exploitation of SQL injection vulnerabilities.",
            "To manage database configurations.",
            "To perform brute force attacks."
        ],
        "answer": "To automate the detection and exploitation of SQL injection vulnerabilities."
    },
    {
        "question": "What does the SQL injection payload '1=1' generally signify when used in a WHERE clause?",
        "options": [
            "The condition will always evaluate to true.",
            "The condition will always evaluate to false.",
            "It checks for user authentication.",
            "It retrieves user passwords."
        ],
        "answer": "The condition will always evaluate to true."
    },
    {
        "question": "When attempting a SQL injection attack, why would an attacker use the 'CAST' function in their payload?",
        "options": [
            "To convert data types and manipulate query results.",
            "To encrypt data in transit.",
            "To hide their identity.",
            "To execute multiple SQL commands."
        ],
        "answer": "To convert data types and manipulate query results."
    },
    {
        "question": "What can be a consequence of an SQL injection attack that allows a hacker to drop database tables?",
        "options": [
            "Loss of data integrity.",
            "Decreased performance.",
            "Increased security risks.",
            "No significant impact."
        ],
        "answer": "Loss of data integrity."
    },
    {
        "question": "A security analyst finds that an application allows the execution of arbitrary SQL commands through an admin interface. What should be the first step in remediation?",
        "options": [
            "Update the application.",
            "Disable the admin interface.",
            "Implement input validation and use parameterized queries.",
            "Increase server resources."
        ],
        "answer": "Implement input validation and use parameterized queries."
    },
    {
        "question": "What is the main purpose of using 'SELECT NULL' in a SQL injection payload?",
        "options": [
            "To confirm the presence of a SQL injection vulnerability.",
            "To retrieve data from a secure database.",
            "To cause a SQL syntax error.",
            "To bypass validation checks."
        ],
        "answer": "To confirm the presence of a SQL injection vulnerability."
    },
    {
        "question": "During an assessment, the application returns a 200 OK status code even when an invalid SQL query is submitted. What does this suggest about the application's error handling?",
        "options": [
            "It is vulnerable to SQL injection.",
            "It uses proper error handling techniques.",
            "It has a custom error page.",
            "It may be using a web application firewall."
        ],
        "answer": "It is vulnerable to SQL injection."
    },
    {
        "question": "A security researcher successfully uses a SQL injection payload to retrieve data from the database. However, the application does not return error messages. Instead, it behaves as if the attack failed. What technique is most likely being used to hide the SQL injection vulnerability?",
        "options": [
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "Stored SQL Injection",
            "Time-based SQL Injection"
        ],
        "answer": "Blind SQL Injection"
    },
    {
        "question": "In a SQL injection context, what does the presence of the 'UNION ALL' operator indicate about the attack?",
        "options": [
            "The attacker is attempting to combine multiple result sets.",
            "The attacker is trying to drop a table.",
            "The attacker is executing a single query.",
            "The attacker is retrieving metadata only."
        ],
        "answer": "The attacker is attempting to combine multiple result sets."
    },
    {
        "question": "An attacker tries to exploit a SQL injection vulnerability by injecting a payload that includes '1; EXEC xp_cmdshell'. What risk does this represent?",
        "options": [
            "SQL injection denial of service.",
            "Command execution on the database server.",
            "Data exfiltration.",
            "Privilege escalation."
        ],
        "answer": "Command execution on the database server."
    },
    {
        "question": "While testing a web application, you notice it uses an ORM (Object-Relational Mapping) framework. What is a common vulnerability that may still exist?",
        "options": [
            "No SQL injection risk exists.",
            "Vulnerable custom queries.",
            "Improper parameterization.",
            "Lack of input validation."
        ],
        "answer": "Vulnerable custom queries."
    },
    {
        "question": "If an application exposes an admin interface that can be accessed without proper authentication, what is the primary concern?",
        "options": [
            "Increased risk of SQL injection.",
            "User enumeration.",
            "Data leakage through URLs.",
            "Brute-force attacks on admin credentials."
        ],
        "answer": "Increased risk of SQL injection."
    },
    {
        "question": "An attacker discovers that the application does not properly validate input on a date field. By injecting '2012-01-01' OR 1=1, they manage to retrieve all records. What type of SQL injection is demonstrated here?",
        "options": [
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "Time-based SQL Injection",
            "In-band SQL Injection"
        ],
        "answer": "In-band SQL Injection"
    },
    {
        "question": "Which of the following best describes a 'Boolean-based blind SQL injection'?",
        "options": [
            "Using conditions that return true or false.",
            "Exploiting error messages for data retrieval.",
            "Combining results from different databases.",
            "Injecting time delays to test for vulnerabilities."
        ],
        "answer": "Using conditions that return true or false."
    },
    {
        "question": "What kind of risk does a lack of input sanitization in a query string pose?",
        "options": [
            "Potential for SQL injection attacks.",
            "Loss of session management.",
            "Increased server load.",
            "Vulnerabilities to cross-site scripting."
        ],
        "answer": "Potential for SQL injection attacks."
    },
    {
        "question": "An attacker manages to extract a list of all tables in the database using 'UNION SELECT NULL, table_name FROM information_schema.tables'. What type of SQL injection is this?",
        "options": [
            "In-band SQL Injection",
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "Stored SQL Injection"
        ],
        "answer": "In-band SQL Injection"
    },
    {
        "question": "When an attacker injects 'OR 1=1--' into a login form, what does the '--' do?",
        "options": [
            "It terminates the current query.",
            "It comments out the rest of the SQL statement.",
            "It creates a new condition.",
            "It invokes an error."
        ],
        "answer": "It comments out the rest of the SQL statement."
    },
    {
        "question": "If an application uses a vulnerable version of a database that allows 'Out-of-Band' SQL injection, what does this imply?",
        "options": [
            "Data can be extracted via alternative channels.",
            "The application is immune to SQL injection.",
            "Only local SQL queries can be executed.",
            "It does not accept any user input."
        ],
        "answer": "Data can be extracted via alternative channels."
    },
    {
        "question": "When performing SQL injection testing, the use of 'ORDER BY' in a payload is often intended to accomplish what?",
        "options": [
            "Manipulate the output of the SQL query.",
            "Extract database error messages.",
            "Test for the number of columns in a response.",
            "Delay the response for timing attacks."
        ],
        "answer": "Test for the number of columns in a response."
    },
    {
        "question": "Which of the following is an indicator that an application is vulnerable to SQL injection during a test?",
        "options": [
            "Consistent output for various inputs.",
            "The application accepts numeric inputs only.",
            "Unexpected application behavior when specific strings are entered.",
            "Data is always returned in JSON format."
        ],
        "answer": "Unexpected application behavior when specific strings are entered."
    },
    {
        "question": "If a SQL injection attack allows an attacker to read from the database logs, what kind of impact does this represent?",
        "options": [
            "Denial of service.",
            "Data leakage.",
            "Privilege escalation.",
            "Command injection."
        ],
        "answer": "Data leakage."
    },
    {
        "question": "What would be the primary purpose of using the 'HAVING' clause in a SQL injection attack?",
        "options": [
            "To filter results after aggregation.",
            "To modify database records.",
            "To create new users.",
            "To bypass input validation."
        ],
        "answer": "To filter results after aggregation."
    },
    {
        "question": "An attacker successfully uses a SQL injection to modify the underlying database schema. What type of SQL injection attack is this likely to be?",
        "options": [
            "In-band SQL Injection",
            "Stored SQL Injection",
            "Time-based SQL Injection",
            "Error-based SQL Injection"
        ],
        "answer": "Stored SQL Injection"
    },
    {
        "question": "Which of the following techniques would an attacker use to escalate privileges through SQL injection?",
        "options": [
            "Retrieving the admin password.",
            "Dropping critical tables.",
            "Creating new admin accounts.",
            "Bypassing authentication checks."
        ],
        "answer": "Creating new admin accounts."
    },
    {
        "question": "During a penetration test, the tester discovers that a web application can execute system commands through SQL injection. What is the primary risk associated with this?",
        "options": [
            "Cross-site scripting.",
            "Remote code execution.",
            "Data manipulation.",
            "Session fixation."
        ],
        "answer": "Remote code execution."
    },
    {
        "question": "An application uses 'input sanitization' but still allows SQL injection. What could be a likely reason?",
        "options": [
            "The sanitization is incomplete or improperly implemented.",
            "The application is using a secure database.",
            "All user inputs are sanitized.",
            "The application is not exposed to the internet."
        ],
        "answer": "The sanitization is incomplete or improperly implemented."
    },
    {
        "question": "What does the 'INFORMATION_SCHEMA' provide in the context of SQL databases?",
        "options": [
            "User authentication methods.",
            "Database metadata and schema details.",
            "Application performance metrics.",
            "Network connection settings."
        ],
        "answer": "Database metadata and schema details."
    },
    {
        "question": "A SQL injection payload is crafted to test the presence of a vulnerability by appending a large string to a query. What technique is this primarily testing?",
        "options": [
            "Error handling.",
            "Input length restrictions.",
            "Response time.",
            "Data integrity."
        ],
        "answer": "Input length restrictions."
    },
    {
        "question": "If a web application allows the injection of a SQL payload that alters a stored procedure, what is the potential outcome?",
        "options": [
            "Increased application performance.",
            "Unauthorized data manipulation.",
            "Improved security posture.",
            "Data encryption."
        ],
        "answer": "Unauthorized data manipulation."
    },
    {
        "question": "In a testing scenario, if an attacker sees that 'SELECT user, password FROM users WHERE id = 1' returns user credentials, which attack vector is being utilized?",
        "options": [
            "In-band SQL Injection",
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "Stored SQL Injection"
        ],
        "answer": "In-band SQL Injection"
    },
    {
        "question": "During a SQL injection assessment, you discover that the application returns different outputs based on the case sensitivity of the input. What does this imply about the database?",
        "options": [
            "It is case-sensitive.",
            "It is case-insensitive.",
            "It is vulnerable to SQL injection.",
            "It has no impact on security."
        ],
        "answer": "It is case-sensitive."
    },
    {
        "question": "If an attacker uses a SQL injection payload that includes 'DECLARE @var VARCHAR(8000)', what is their intention?",
        "options": [
            "To retrieve variable data.",
            "To define a variable for use in the query.",
            "To bypass input validation.",
            "To comment out the SQL statement."
        ],
        "answer": "To define a variable for use in the query."
    },
    {
        "question": "In a scenario where an attacker successfully injects into a SQL query that retrieves logs, what is the most critical risk?",
        "options": [
            "Application downtime.",
            "Data corruption.",
            "Exposure of sensitive information.",
            "Loss of user sessions."
        ],
        "answer": "Exposure of sensitive information."
    },
    {
        "question": "An attacker successfully executes 'SELECT * FROM users WHERE username = '' OR '1'='1'';' on a login form. What type of SQL injection is being performed?",
        "options": [
            "In-band SQL Injection",
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "Time-based SQL Injection"
        ],
        "answer": "In-band SQL Injection"
    },
    {
        "question": "While testing a web application, you find that it returns different response times based on injected payloads. What does this indicate about the application?",
        "options": [
            "It is vulnerable to Time-based SQL Injection.",
            "It has implemented proper input validation.",
            "The application is secure.",
            "The database is down."
        ],
        "answer": "It is vulnerable to Time-based SQL Injection."
    },
    {
        "question": "During an SQL injection test, an attacker uses the payload '1; DROP TABLE users;--'. What does this payload attempt to accomplish?",
        "options": [
            "Retrieve user data.",
            "Delete the users table.",
            "Alter user privileges.",
            "Bypass authentication."
        ],
        "answer": "Delete the users table."
    },
    {
        "question": "If a web application allows the injection of 'SELECT database()' and returns the current database name, what does this signify?",
        "options": [
            "The application is using stored procedures.",
            "The application is vulnerable to SQL injection.",
            "The application has strong input validation.",
            "The database connection is secure."
        ],
        "answer": "The application is vulnerable to SQL injection."
    },
    {
        "question": "An attacker attempts to use 'IF EXISTS(SELECT * FROM users WHERE username = '' OR 1=1)' to gain unauthorized access. What type of SQL injection is this demonstrating?",
        "options": [
            "Union-based SQL Injection",
            "Boolean-based Blind SQL Injection",
            "Error-based SQL Injection",
            "In-band SQL Injection"
        ],
        "answer": "Boolean-based Blind SQL Injection"
    },
    {
        "question": "What is a primary defense mechanism against SQL injection in web applications?",
        "options": [
            "Obfuscating SQL queries.",
            "Using input validation and parameterized queries.",
            "Encrypting database connections.",
            "Deploying a web application firewall."
        ],
        "answer": "Using input validation and parameterized queries."
    },
    {
        "question": "During a SQL injection attack, an attacker injects 'WAITFOR DELAY ''0:0:5'';'. What is the purpose of this payload?",
        "options": [
            "To retrieve hidden data.",
            "To introduce a delay for timing attacks.",
            "To check for syntax errors.",
            "To manipulate database records."
        ],
        "answer": "To introduce a delay for timing attacks."
    },
    {
        "question": "If an application logs detailed error messages that include SQL queries, what risk does this pose during a SQL injection attack?",
        "options": [
            "Improved debugging.",
            "Enhanced application performance.",
            "Increased attack surface due to information disclosure.",
            "No significant risk."
        ],
        "answer": "Increased attack surface due to information disclosure."
    }


]
;

  // Shuffle array function
function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
}

// Shuffle questions and options initially
shuffleArray(questions);
questions.forEach(question => shuffleArray(question.options));

const questionStatus = Array(questions.length).fill("unanswered"); // Track status of each question

function loadQuestion() {
    const questionData = questions[currentQuestion];
    document.getElementById("question").innerText = `Q${currentQuestion + 1}: ${questionData.question}`;

    // Shuffle options for the current question
    shuffleArray(questionData.options);

    const optionsContainer = document.getElementById("options");
    optionsContainer.innerHTML = '';
    questionData.options.forEach(option => {
        const button = document.createElement("div");
        button.className = "option";
        button.innerText = option;
        button.onclick = () => checkAnswer(option);
        optionsContainer.appendChild(button);
    });

    updateSidebar();
    updateNavigationButtons();
    updateRemainingQuestions();
}

function checkAnswer(selected) {
    const correctAnswer = questions[currentQuestion].answer;
    const options = document.querySelectorAll(".option");

    options.forEach(option => {
        option.onclick = null; // Disable further clicks
        if (option.innerText === correctAnswer) {
            option.classList.add("correct");
        } else {
            option.classList.add("incorrect");
        }
    });

    if (selected === correctAnswer) {
        correctAnswers++;
        questionStatus[currentQuestion] = "completed";
    } else {
        wrongAnswers++;
        questionStatus[currentQuestion] = "incorrect";
    }
    updateSidebar();
}

function skipQuestion() {
    questionStatus[currentQuestion] = "skipped";
    loadNextQuestion();
}

function loadNextQuestion() {
    currentQuestion++;
    if (currentQuestion < questions.length) {
        loadQuestion();
    } else {
        showFinalScore();
    }
}

function loadPreviousQuestion() {
    if (currentQuestion > 0) {
        currentQuestion--;
        loadQuestion();
    }
}

function restartQuiz() {
    currentQuestion = 0;
    correctAnswers = 0;
    wrongAnswers = 0;
    questionStatus.fill("unanswered"); // Reset question status to "unanswered"
    shuffleArray(questions); // Shuffle questions for the new session
    questions.forEach(question => shuffleArray(question.options)); // Shuffle options for each question
    loadQuestion(); // Load the first question again
    updateSidebar(); // Reset the question status sidebar
}

function updateRemainingQuestions() {
    const totalQuestions = questions.length;
    const remainingQuestions = totalQuestions - currentQuestion - 1;
    document.getElementById("remaining-questions").innerText = remainingQuestions;
}

function updateSidebar() {
    const statusContainer = document.getElementById("status");
    statusContainer.innerHTML = '';
    questions.forEach((_, index) => {
        const bubble = document.createElement("div");
        bubble.className = "bubble";
        bubble.innerText = index + 1;

        // Update bubble color based on question status
        if (questionStatus[index] === "completed") {
            bubble.classList.add("completed");
        } else if (questionStatus[index] === "skipped") {
            bubble.classList.add("skipped");
        } else if (questionStatus[index] === "incorrect") {
            bubble.classList.add("incorrect");
        }

        statusContainer.appendChild(bubble);
    });
}

function updateNavigationButtons() {
    document.getElementById("prev").classList.toggle("hidden", currentQuestion === 0);
    document.getElementById("next").innerText = questionStatus[currentQuestion] === "skipped" ? "Resume" : "Next";
}

// Event listeners for buttons
document.getElementById("next").onclick = () => {
    if (questionStatus[currentQuestion] === "unanswered") {
        skipQuestion();
    } else {
        loadNextQuestion();
    }
};

document.getElementById("prev").onclick = loadPreviousQuestion;

document.getElementById("restart").onclick = restartQuiz;

document.getElementById("submit").onclick = showFinalScore;

function showFinalScore() {
    const resultContainer = document.createElement("div");
    resultContainer.className = "quiz-container";

    resultContainer.innerHTML = `
        <h1>Quiz Completed</h1>
        <p>Questions: ${questions.length}</p>
        <p>Correct: ${correctAnswers}</p>
        <p>Wrong: ${wrongAnswers}</p>
        <p>Total Score: ${correctAnswers} out of ${questions.length}</p>
    `;

    const restartButton = document.createElement("button");
    restartButton.id = "restart";
    restartButton.className = "btn";
    restartButton.innerText = "Restart Quiz";
    restartButton.onclick = restartQuiz;

    resultContainer.appendChild(restartButton);

    document.body.innerHTML = ''; // Clear existing content
    document.body.appendChild(resultContainer); // Add results
}

// Load the first question
loadQuestion();