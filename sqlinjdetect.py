import sys

demo1 = "SELECT @CMD = 'SELECT * FROM Person.Person"
demo2 = "INSERT INTO users VALUES ('admin', 'e1568c571e684e0fb1724da85d215dc0', 'admin')"
demo3 = "INSERT INTO Customers (CustomerName, City, Country) SELECT SupplierName, City, Country FROM Suppliers WHERE " \
        "Country='Germany'; "
demo4 = "SELECT SupplierName, City, Country FROM Suppliers WHERE Country='Germany';"
demo5 = "FROM Suppliers WHERE Country='Germany';"


def check_for_sql_inj(data):
    
    # sql_keys = ['ADD', 'ALTER', 'ALTERCOLUMN', 'ALTERTABLE', 'ALL', 'AND', 'ANY', 'AS', 'ASC', 'BACKUPDATABASE',
    # 'BETWEEN', 'CASE', 'CHECK', 'COLUMN', 'CONSTRAINT', 'CREATE', 'CREATEDATABASE', 'CREATEINDEX',
    # 'CREATEORREPLACEVIEW', 'CREATETABLE', 'CREATEPROCEDURE', 'CREATEUNIQUEINDEX', 'CREATEVIEW', 'DELETE',
    # 'DISTINCT', 'DROP', 'DROPCOLUMN', 'DROPCONSTRAINT', 'DROPDATABASE', 'DROPDEFAULT', 'DROPINDEX', 'DROPTABLE',
    # 'DROPVIEW', 'EXEC', 'EXISTS', 'FOREIGNKEY', 'FROM', 'FULLOUTERJOIN', 'GROUPBY', 'HAVING', 'IN', 'INDEX',
    # 'INNERJOIN', 'INSERTINTO', 'INSERTINTOSELECT', 'ISNULL', 'ISNOTNULL', 'JOIN', 'LEFTJOIN', 'LIKE', 'LIMIT',
    # 'NOT', 'NOTNULL', 'OR', 'ORDERBY', 'OUTERJOIN', 'PRIMARYKEY', 'PROCEDURE', 'RIGHTJOIN', 'ROWNUM', 'SELECT',
    # 'SELECTDISTINCT', 'SELECTINTO', 'SELECTTOP', 'SET', 'TABLE', 'TOP', 'TRUNCATETABLE', 'UNION', 'UNIONALL',
    # 'UNIQUE', 'UPDATE', 'VALUES', 'VIEW', 'WHERE']

    sql_keys = ['INSERT', 'INTO', 'VALUES', 'SELECT', 'FROM', 'WHERE']
    data = data.lower()
    for key in sql_keys:
        if key.lower() in data:
            print('Sql Injection attempt found!')
            return True
    return False


if __name__ == '__main__':

    demos = [demo1, demo2, demo3]
    for demo in demos:
        check_for_sql_inj(demo)

    sys.exit(0)
