from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd, reqcheck
from time import localtime, strftime


# Configure application
app = Flask(__name__)

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Extract the user's stock name and number of shares from the transactions table, only include if number of shares > 0
    stockshares = db.execute("SELECT stockname, sum(shares) FROM transactions WHERE userid = :userid GROUP BY stockname HAVING SUM(shares) > 0",
                             userid=session["user_id"])
    user = db.execute("SELECT * FROM users WHERE id = :userid",
                      userid=session["user_id"])
    # Look up the current price of each stock, add it to the stockshare list, calculate the total value for each stock, subtract it from the remaining cash, and convert money to usd format
    totalvalue = 0
    for stock in stockshares:
        stock["price"] = lookup(stock["stockname"])["price"]
        stock["total"] = stock["price"] * stock["sum(shares)"]
        totalvalue += stock["total"]
        stock["price"] = usd(stock["price"])
        stock["total"] = usd(stock["total"])

    return render_template("index.html", username=user[0]["username"], stockshares=stockshares, cash=usd(user[0]["cash"]), grandtotal=usd(user[0]["cash"] + totalvalue))


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # ensure a stock is selected
        if not request.form.get("symbol"):
            return apology("must select a stock")
        # look up stock's quote
        stockquote = lookup(request.form.get("symbol"))
        # ensure the stock symbol is valid
        if not stockquote:
            return apology("invalid stock symbol")
        # ensure the user own the stock selected
        stock = db.execute("SELECT sum(shares) FROM transactions WHERE userid = :userid AND stockname = :stockname GROUP BY stockname HAVING sum(shares) > 0",
                           userid=session["user_id"], stockname=stockquote["name"])
        if len(stock) == 0:
            return apology("sorry, you do not own any shares of this stock")
        # ensure number of shares is a positive integer
        try:
            numshares = int(request.form.get("shares"))
        except ValueError:
            return apology("number of shares must be a positive integer")
        if numshares <= 0:
            return apology("number of shares must be greater than 0")
        # ensure the user owns sufficient number of stock
        if numshares > stock[0]["sum(shares)"]:
            return apology("you do not own that many shares of this stock")
        # add the transaction in the transactions table
        transid = db.execute("INSERT INTO transactions (userid, stockname, price, shares, time) VALUES (:userid, :stockname, :price, :shares, :time)",
                             userid=session["user_id"], stockname=stockquote["name"], price=stockquote["price"], shares=-numshares, time=strftime("%Y-%m-%d %H:%M:%S", localtime()))
        # look up the user's cash
        cash = db.execute("SELECT cash FROM users WHERE id = :userid", userid=session["user_id"])
        remaining = cash[0]["cash"] + numshares * stockquote["price"]
        # update cash amount in the users table
        db.execute("UPDATE users SET cash = :cash WHERE id = :userid",
                   cash=remaining, userid=session["user_id"])
        # render transaction confirmation page
        return render_template("transconf.html", transid=transid, transtype="SELL", stockname=stockquote["name"], price=usd(stockquote["price"]), shares=numshares, total=usd(-stockquote["price"] * numshares), cash=usd(remaining))

    else:
        # get the user's remaining stock
        stocks = db.execute("SELECT stockname, sum(shares) FROM transactions WHERE userid = :userid GROUP BY stockname HAVING sum(shares) > 0",
                            userid=session["user_id"])
        return render_template("sell.html", stocks=stocks)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure stock's symbol is entered
        if not request.form.get("symbol"):
            return apology("must enter stock's symbol")
        # look up the stock's price
        stockquote = lookup(request.form.get("symbol"))
        # Ensure valid stock symbol
        if not stockquote:
            return apology("invalid stock symbol")
        # Ensure number of shares is a positive integer
        try:
            numshares = int(request.form.get("shares"))
        except ValueError:
            return apology("number of shares must be a positive integer")
        if numshares <= 0:
            return apology("number of shares must be greater than 0")
        # look up the user's cash
        cash = db.execute("SELECT cash FROM users WHERE id = :userid",
                          userid=session["user_id"])
        # ensure the user has sufficient cash
        remaining = cash[0]["cash"] - stockquote["price"] * numshares
        if remaining < 0:
            return apology("insufficient cash")
        # update cash amount in the users table
        db.execute("UPDATE users SET cash = :cash WHERE id = :userid",
                   cash=remaining, userid=session["user_id"])
        # add the transaction in the purchase table, and save the transaction number
        transid = db.execute("INSERT INTO transactions (userid, stockname, price, shares, time) VALUES (:userid, :stockname, :price, :shares, :time)",
                             userid=session["user_id"], stockname=stockquote["name"], price=stockquote["price"], shares=numshares, time=strftime("%Y-%m-%d %H:%M:%S", localtime()))
        # render transaction confirmation page
        return render_template("transconf.html", transid=transid, transtype="BUY", stockname=stockquote["name"], price=usd(stockquote["price"]), shares=numshares, total=usd(stockquote["price"] * numshares), cash=usd(remaining))
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Select user's transaction history from database
    transactions = db.execute("SELECT * FROM transactions WHERE userid = :userid", userid=session["user_id"])
    for transaction in transactions:
        if transaction["shares"] > 0:
            transaction["type"] = "BUY"
        else:
            transaction["type"] = "SELL"
        transaction["total"] = usd(transaction["shares"] * transaction["price"])
        transaction["price"] = usd(transaction["price"])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        info = lookup(request.form.get("symbol"))
        try:
            return render_template("quoted.html", name=info["name"], price=usd(info["price"]), symbol=info["symbol"])
        except:
            return apology("Stock Quote Not Found")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # If username was submitted, ensure username does not exist
        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if len(rows) != 0:
            return apology("username already exists")

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password")

        # Ensure password satisfies requirement
        if not reqcheck(request.form.get("password")):
            return apology("password does not satisfy the requirements")

        # Ensure password was confirmed:
        if not request.form.get("confirmation"):
            return apology("must confirm password")

        # Ensure passwords match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match")

        # Add user to database
        session["user_id"] = db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
                                        username=request.form.get("username"), password=generate_password_hash(request.form.get("password")))

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/changepw", methods=["GET", "POST"])
@login_required
def changepw():
    """Change user's password"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure old password was submitted
        if not request.form.get("oldpassword"):
            return apology("must provide old password")

        # Ensure old password is correct
        rows = db.execute("SELECT * FROM users WHERE id = :userid",
                          userid=session["user_id"])

        if not check_password_hash(rows[0]["hash"], request.form.get("oldpassword")):
            return apology("old password is incorrect")

        # Ensure new password was submitted
        if not request.form.get("newpassword"):
            return apology("must provide new password")

        # Ensure password satisfies requirement
        if not reqcheck(request.form.get("newpassword")):
            return apology("new password does not satisfy the requirements")

        # Ensure new password was confirmed:
        if not request.form.get("confirmation"):
            return apology("must confirm new password")

        # Ensure new passwords match
        if request.form.get("newpassword") != request.form.get("confirmation"):
            return apology("new passwords do not match")

        # Update password
        db.execute("UPDATE users SET hash = :password WHERE id = :userid",
                   userid=session["user_id"], password=generate_password_hash(request.form.get("newpassword")))

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("changepw.html")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
