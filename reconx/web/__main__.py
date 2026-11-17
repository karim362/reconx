from reconx.web.app import app
if __name__ == "__main__":
    print("\n  ReconX Dashboard -> http://localhost:8000\n")
    app.run(host="0.0.0.0", port=8000, debug=False, threaded=True)
