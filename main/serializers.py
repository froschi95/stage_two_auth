from rest_framework import serializers
from .models import User, Organisation

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['user_id', 'first_name', 'last_name', 'email', 'password', 'phone']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate(self, data):
        if 'email' in data:
            if User.objects.filter(email=data['email']).exists():
                raise serializers.ValidationError({'email': 'Email must be unique'})
        return data

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

class OrganisationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ['org_id', 'name', 'description']


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class AddUserToOrganisationSerializer(serializers.Serializer):
    user_id = serializers.UUIDField()
    # org_id = serializers.UUIDField()