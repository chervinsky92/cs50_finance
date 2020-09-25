# export API_KEY=pk_1310db0d95ab45dcac14697c66d7c39a

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
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        stock_info = lookup(symbol)


        # Make sure tracker is valid
        if stock_info == None:
            return apology("invalid symbol", 400)

        # At least one share selected to purchase
        if shares == '':
            return apology("cannot buy 0 shares", 400)

        stock_price = stock_info["price"]

        # Query database for current user's cash
        user_cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]["cash"]

        # Purchase shares
        purchase = stock_price * int(shares)
        if purchase > user_cash:
            return apology("cannot afford", 400)

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
        db.execute("INSERT INTO transactions ('user_id', 'symbol', 'amount', 'price', 'date') VALUES (:id, :symbol, :amount, :price, :date)", id=session["user_id"], symbol=symbol, amount=shares, price=purchase, date=datetime.now())
        # Return user to home page
        return redirect("/")
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


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
            return apology("invalid symbol", 400)

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
            return apology("must provide username", 400)

        # Password fields are filled out
        if not password or not password_confirmation:
            return apology("must provide password", 400)

        # Passwords match
        if password != password_confirmation:
            return apology("passwords do not match", 400)

        # Check if username already exists
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
        if rows[0]["username"] == username:
            return apology("username already exists", 400)

        # Hash password
        hash = generate_password_hash(password)

        # Insert new user into users table
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=hash)
        return redirect("/")
    else:
        return render_template("register.html")




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
