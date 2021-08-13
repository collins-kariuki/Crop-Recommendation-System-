import requests


def get_weather(city_name):
    # api_key = os.environ['WEATHER_KEY']
    api_key = 'f52529d7dd3c6879c20b41b0c8d73923'
    base_url = "http://api.openweathermap.org/data/2.5/weather?"
    complete_url = base_url + "appid=" + api_key + "&q=" + city_name
    response = requests.get(complete_url)
    x = response.json()

    if x["cod"] != "404":  # rename variables.
        y = x["main"]

        temperature = round((y["temp"] - 273.15), 2)
        humidity = y["humidity"]
        return temperature, humidity
    else:
        return None
