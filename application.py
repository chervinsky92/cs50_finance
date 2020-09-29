import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

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

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    # stocks = a list of dictionaries
    # Each dictionary item represents a symbol that the user owns shares of
    stocks = db.execute("SELECT * FROM stocks WHERE user_id = :id", id=session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]["cash"]

    # stock_cash tracks how much $ user owns in stocks
    stock_cash = 0
    # Add name, price, and total keys to each dictionary item that will exist for the duration of the function call
    for stock in stocks:
        stock["name"] = lookup(stock["symbol"])["name"]
        stock["price"] = float(lookup(stock["symbol"])["price"])

        # stock_value = how much $ user owns from a symbol
        stock_value = stock["price"] * stock["shares"]
        stock_cash += stock_value

        # Convert to dollar format
        stock["price"] = usd(stock["price"])
        stock["total"] = str(usd(stock_value))

    # Convert to dollar format
    total_cash = usd(cash + stock_cash)
    cash = usd(cash)

    return render_template("index.html", cash=cash, total_cash=total_cash, stocks=stocks)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        stock_info = lookup(symbol)

        # Make sure tracker is valid
        if stock_info == None:
            return apology("invalid symbol")

        # At least one share selected to purchase
        if shares == '':
            return apology("cannot buy 0 shares")

        stock_price = stock_info["price"]

        # Query database for current user's cash
        user_cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]["cash"]

        # Purchase shares
        purchase = stock_price * int(shares)
        if purchase > user_cash:
            return apology("cannot afford")

        # Check if user already owns shares of the symbol they are trying to buy
        try:
            existing_shares = db.execute("SELECT * FROM stocks WHERE user_id = :id AND symbol = :symbol", id=session["user_id"], symbol=symbol)[0]["symbol"]
        except:
            existing_shares = False

        # No previous shares owned
        if not existing_shares:
            db.execute("INSERT INTO stocks ('user_id', 'symbol', 'shares') VALUES (:id, :symbol, :shares)", id=session["user_id"], symbol=symbol, shares=shares)
        # Update share count
        else:
            db.execute("UPDATE stocks SET shares = shares + :shares WHERE user_id = :id AND symbol = :symbol", shares=shares, id=session["user_id"], symbol=symbol)

        # Update user's cash amount
        db.execute("UPDATE users SET cash = :cash WHERE id= :id", cash=(user_cash - purchase), id=session["user_id"])

        # Add transaction to transactions table
        db.execute("INSERT INTO transactions ('user_id', 'symbol', 'amount', 'price', 'date') VALUES (:id, :symbol, :amount, :price, :date)", id=session["user_id"], symbol=symbol, amount=shares, price=stock_price, date=datetime.now())

        # Return user to home page
        flash("Bought!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():
    cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]["cash"]

    if request.method == "POST":
        requested_cash = int(request.form.get("cash"))

        # Add a positive cash value
        if requested_cash < 1:
            return apology("Add at least $1")

        # Update user's new cash amount in database
        new_amount = cash + requested_cash
        db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=new_amount, id=session["user_id"])

        # Redirect back to dashboard
        flash("Money Added!")
        return redirect("/")

    else:
        cash = usd(cash)
        return render_template("cash.html", cash_amount=cash)


@app.route("/history")
@login_required
def history():
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = :id", id=session["user_id"])

    for transaction in transactions:
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
        elif not request.form.get("password"):
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
    if request.method == "POST":
        symbol = request.form.get("symbol")
        stock_info = lookup(symbol)

        # Make sure tracker is valid
        if stock_info == None:
            return apology("invalid symbol")

        # Return stock name and price
        stock_name = stock_info["name"]
        stock_symbol = stock_info["symbol"]
        stock_price = stock_info["price"]
        return render_template("quoted.html", stock_name=stock_name, stock_symbol=stock_symbol, stock_price=stock_price)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        password_confirmation = request.form.get("password_confirmation")

        # Username field is not blank
        if not username:
            return apology("must provide username")

        # Password fields are filled out
        if not password or not password_confirmation:
            return apology("must provide password")

        # Passwords match
        if password != password_confirmation:
            return apology("passwords do not match")

        # Check if username already exists
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
        if rows[0]["username"] == username:
            return apology("username already exists")

        # Hash password
        hash = generate_password_hash(password)

        # Insert new user into users table
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=hash)

        # Redirect user to dashboard
        flash("Registered!")
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        stocks = db.execute("SELECT * FROM stocks WHERE user_id = :id", id=session["user_id"])

        # A symbol must be chosen
        if request.form.get("symbol") == None:
            return apology("missing symbol")
        symbol = request.form.get("symbol").upper()

        # Must sell at least 1 share
        shares_to_sell = int(request.form.get("shares"))
        if shares_to_sell < 1:
            return apology("shares must be positive")

        owned_shares = db.execute("SELECT shares FROM stocks WHERE user_id = :id AND symbol = :symbol", id=session["user_id"], symbol=symbol)[0]["shares"]

        # Check if user owns the shares they are trying to sell
        if shares_to_sell > owned_shares:
            return apology("too many shares")
        # Update shares owned if shares left > 0
        elif owned_shares - shares_to_sell > 0:
            db.execute("UPDATE stocks SET shares = shares - :shares WHERE user_id = :id AND symbol = :symbol", shares=shares_to_sell, id=session["user_id"], symbol=symbol)
        # Delete symbol from stocks owned if there are no shares left after transaction
        else:
            db.execute("DELETE FROM stocks WHERE user_id = :id AND symbol = :symbol", id=session["user_id"], symbol=symbol)

        # Update user cash
        user_cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]["cash"]
        stock_price = lookup(symbol)["price"]
        cash_gained = stock_price * shares_to_sell
        db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=(user_cash + cash_gained), id=session["user_id"])

        # Add transaction to transactions table
        db.execute("INSERT INTO transactions ('user_id', 'symbol', 'amount', 'price', 'date') VALUES (:id, :symbol, :amount, :price, :date)", id=session["user_id"], symbol=symbol, amount=-shares_to_sell, price=stock_price, date=datetime.now())

        # Return user to home page
        flash("Sold!")
        return redirect("/")

    else:
        stocks = db.execute("SELECT * FROM stocks WHERE user_id = :id", id=session["user_id"])
        return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
