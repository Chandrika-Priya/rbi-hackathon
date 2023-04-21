import pandas as pd

df = pd.read_csv("data/data_products.csv", index_col=None)

db_data = []
values = df.values
for i in values:
    print(i, i.shape, tuple(list(i.reshape(1,8))))
    # print(tuple("".join(i).replace('nan', '').split(" ")))
    # db_data.append(tuple("".join(i).replace('nan', '').split(" ")))


print(df.columns.values)
# print(db_data)
# import sqlite3
conn = sqlite3.connect('example2.db')

c = conn.cursor()

# Create table
# c.execute('''CREATE TABLE orders
#              (text, trans text, symbol text, qty real, price real)''')


c.execute('''CREATE TABLE catalogue
    (text, SellerID text, ProductID text, ProdCategory text, ProdName text, ProdPrice real, InventorySize real)''')


# # Insert a row of data
# # c.execute("INSERT INTO stocks VALUES ('2006-01-05','BUY','RHAT',100,35.14)")

# # EXISTING ORDERS
# # Create table
# c.execute('''CREATE TABLE orders
#              (order_date, order_number, order_email, color, size, status)''')

# # data to be added
# purchases = [('2006-01-05',123456,'example@rasa.com','blue', 9, 'shipped'),
#              ('2021-01-05',123457,'me@rasa.com','black', 10, 'order pending'),
#              ('2021-01-05',123458,'me@gmail.com','gray', 11, 'delivered'),
#             ]

# # add data
# c.executemany('INSERT INTO orders VALUES (?,?,?,?,?,?)', purchases)

# # AVAILABLE INVENTORY
# # Create table
# c.execute('''CREATE TABLE inventory
#              (size, color)''')

# # data to be added
# inventory = [(7, 'blue'),
#              (8, 'blue'),
#              (9, 'blue'),
#              (10, 'blue'),
#              (11, 'blue'),
#              (12, 'blue'),
#              (7, 'black'),
#              (8, 'black'),
#              (9, 'black'),
#              (10, 'black')
#             ]

# # add data
# c.executemany('INSERT INTO inventory VALUES (?,?)', inventory)


# # Save (commit) the changes
# conn.commit()

# # end connection
# conn.close()