import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from pytz import utc

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Auto reload
app.debug = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get current user id from session
    user_id = session["user_id"]
    # Get current username and cash as a Dictionary
    user = db.execute("SELECT username, cash FROM users WHERE id = ?", user_id)[0]

    # Get stock name and share amount owned by user as a List of Dictionaries
    assets = db.execute("SELECT DISTINCT stock, SUM(share_amount) as share_amount FROM transactions WHERE user_id = ? GROUP BY stock HAVING SUM(share_amount) != 0 ORDER BY stock", user_id)

    # Grand total of user's cash balance and stocks' total value
    grand_total = user["cash"]
    for asset in assets:
        stock = lookup(asset["stock"])
        grand_total += asset["share_amount"] * stock["price"]

    return render_template("index.html", user=user, assets=assets, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        
        # Getting stock symbol posted by user
        symbol = request.form.get("symbol").strip()

        # If user does not provided stock name
        if not symbol:
            return apology("Must provide the name of stock!", 403)
        
        try:
            # Getting amount of shares to buy posted by user
            shares = request.form.get("shares").strip()

            # If user does not provided the amount of shares
            if not shares:
                return apology("Must provide share amount!", 403)
            shares = float(shares)
        except ValueError:
            return apology("Enter only numeric value in share amount!", 403)
        else:
            # If user provided negative number of shares
            if shares != abs(shares):
                return apology("Must provide with a valid number of share amount!", 403)

        # Get the current value of the stock
        stock = lookup(symbol)

        # If there is no stock that the user is requesting
        if not stock:
            return apology("Stock does not exists", 404)

        # Get current user id
        user_id = session["user_id"]

        # Get user's available money and total cost to buy stocks
        available_money = float(db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"])
        cost = stock["price"] * shares
        # If user's money is insufficient to buy shares
        if available_money < cost:
            return apology("Insufficient cash!", 403)
        
        # Get current UTC time
        current_utc_time = utc.localize(datetime.now()).replace(microsecond=0, tzinfo=None)
        
        # Add the purchase history into the database
        db.execute( """
                    INSERT INTO transactions (user_id, transaction_type, stock, price, share_amount, datetime)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    user_id,
                    'buy',
                    stock["symbol"],
                    stock["price"],
                    shares,
                    current_utc_time
                    )
        
        # Subtract cost from the user's cash balance
        db.execute("""
                   UPDATE users
                   SET cash = ?
                   WHERE id = ?
                   """, available_money - cost, user_id)
        
        # Redirect user back to the home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy-stock.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute("SELECT stock, transaction_type, price, share_amount, datetime FROM transactions WHERE user_id = ? ORDER BY id DESC", session["user_id"])

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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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

    # User reached route via POST (as by submitting a form via post)
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # If user does not provided a stock name
        if not symbol:
            return apology("Must provide the name of stock!", 403)

        # Get the price and symbol of the stock
        stock = lookup(symbol)

        # If the stock is not found
        if not stock:
            return apology("Stock not found", 404)
        
        # Show the stock details page
        return render_template("quoted.html", stock_name=stock["symbol"], stock_price=stock["price"])

    # User reached route via GET (as by clicking a link)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # If user is submitting the register form
    if request.method == "POST":
        # Remove any space at the start and end of username, password and confirm password
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        confirm_password = request.form.get("confirm_password").strip()

        # If username field is not provided
        if not username:
            return apology("Must provide a username", 403)
        
        # If password field is not provided
        elif not password:
            return apology("Must provide a password", 403)
        
        # If confirm password field is not provided
        elif not password:
            return apology("Must provide a confirm password", 403)

        # If two provided passwords don't match
        elif not password == confirm_password:
            return apology("Password don't match", 403)
        
        else:
            try:
                # Add new user into the database
                db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))

                # Auto login after success user registration
                rows = db.execute("SELECT * FROM users WHERE username = ?", username)
                session["user_id"] = rows[0]["id"]

                # Redirect user to home page
                return redirect("/")
            except ValueError:
                return apology("User already exists!", 403)

    # Go to the register form
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        
        # Getting stock symbol posted by user
        symbol = request.form.get("symbol").strip()

        # If user does not provided stock name
        if not symbol:
            return apology("Must provide the name of stock!", 403)
        
        try:
            # Getting amount of shares to buy posted by user
            shares = request.form.get("shares").strip()

            # If user does not provided the amount of shares
            if not shares:
                return apology("Must provide share amount!", 403)
            
            shares = float(shares)
        except ValueError:
            return apology("Enter only numeric value in share amount!", 403)
        else:
            # If user provided negative number of shares
            if shares != abs(shares):
                return apology("Must provide with a valid number of share amount!", 403)

        # Get the current value of the stock
        stock = lookup(symbol)

        # If there is no stock that the user is requesting
        if not stock:
            return apology("Stock does not exists", 404)

        # Get current user id
        user_id = session["user_id"]

        # Get the name of all stocks owned by the user
        own_stocks_dict = db.execute("SELECT DISTINCT stock FROM transactions WHERE user_id = ? GROUP BY stock HAVING SUM(share_amount) != 0 ORDER BY stock", user_id)
        own_stocks = []
        for own_stock_dict in own_stocks_dict:
            own_stocks.append(own_stock_dict["stock"])
        
        # If user does not own the stock
        if not stock["symbol"] in own_stocks:
            return apology("Does not own any shares of the stock!", 403)

        # Get user's available stock share
        available_share = float(db.execute("SELECT SUM(share_amount) AS share_amount FROM transactions WHERE user_id = ? AND stock = ?", user_id, stock["symbol"])[0]["share_amount"])
        # If user's available stock shares to sell is insufficient
        if available_share < shares:
            return apology("Insufficient share!", 403)
        
        # Get current UTC time
        current_utc_time = utc.localize(datetime.now()).replace(microsecond=0, tzinfo=None)

        # Get user's current owned cash
        owned_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        
        # Add the purchase history into the database
        db.execute( """
                    INSERT INTO transactions (user_id, transaction_type, stock, price, share_amount, datetime)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    user_id,
                    'sell',
                    stock["symbol"],
                    stock["price"],
                    -shares,
                    current_utc_time
                    )
        
        # Add received cash from selling to the user's cash balance
        db.execute("""
                   UPDATE users
                   SET cash = ?
                   WHERE id = ?
                   """, owned_cash + (shares * stock["price"]), user_id)

        return redirect("/")
    else:
        return render_template("sell-stock.html")
    

@app.route("/profile")
def profile():
    """Watch user profile"""

    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]

    return render_template("profile.html", username=username)


@app.route("/change-username", methods=["POST"])
def change_username():
    """Change username"""

    # Get new username and confirm password from user input
    new_username = request.form.get("newusername")
    password = request.form.get("password")

    # Get hashed password from the database
    correct_password = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]

    # If confirmed password is not correct
    if not check_password_hash(correct_password, password):
        return apology("Incorrect password", 403)
    
    # Change username
    db.execute("UPDATE users SET username = ? WHERE id = ?", new_username, session["user_id"])

    # Redirect user to the homepage
    return redirect("/")


@app.route("/change-password", methods=["POST"])
def change_password():
    """Change password"""

    # Get new password and confirm password from user input
    new_password = request.form.get("newpassword")
    current_password = request.form.get("currentpassword")

    # Get hashed password from the database
    correct_password = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]

    # If confirmed password is not correct
    if not check_password_hash(correct_password, current_password):
        return apology("Incorrect password", 403)
    
    # Change password
    db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password), session["user_id"])

    # Redirect user to the homepage
    return redirect("/")


@app.route("/test")
def test():
    # return {key: value for key, value in session.items()}
    return f"value is {db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]}"