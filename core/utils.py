from .models import UserDataLogger

def create_user_data_log(user_data,**kwargs):
    """
    Utility function to create a UserDataLogger entry.

    Args:
        user_data (UserData): The UserData object to link the log with.
        battery (int, optional): Battery level.
        gps_lat (float, optional): Latitude.
        gps_lon (float, optional): Longitude.
        mood (str, optional): Mood string.
        note (str, optional): Message/note.

    Returns:
        UserDataLogger: The created log entry.
    """
    return UserDataLogger.objects.create(
        user_data=user_data,
        **kwargs
    )
