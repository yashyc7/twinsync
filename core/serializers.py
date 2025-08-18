# core/serializers.py
from rest_framework import serializers
from core.models import UserData
from django.contrib.auth import get_user_model,authenticate


User=get_user_model()


class UserDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserData
        fields = ["battery", "steps", "gps_lat", "gps_lon", "mood", "updated_at"]
        
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "display_name", "firebase_uid"]
        
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "password", "display_name"]

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create_user(password=password, **validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(email=data["email"], password=data["password"])
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        return user
