from rest_framework import generics, status
from rest_framework.response import Response
# from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from django.contrib.auth import authenticate
from .tokens import CustomRefreshToken
from .models import User, Organisation
from .serializers import UserSerializer, OrganisationSerializer, LoginSerializer, AddUserToOrganisationSerializer
from rest_framework.exceptions import ValidationError
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction


class RegisterView(generics.CreateAPIView):
    serializer_class = UserSerializer

    @transaction.atomic
    def perform_create(self, serializer):
        try:
            user = serializer.save()
            org_name = f"{user.first_name}'s Organisation"
            org = Organisation.objects.create(name=org_name)
            org.users.set([user])
        except ValidationError as e:
            raise ValidationError({
                'errors': [{'field': key, 'message': value[0]} for key, value in e.detail.items()],
            })

    def create(self, request, *args, **kwargs):
        try:
            response = super().create(request, *args, **kwargs)
            user = response.data
            refresh = CustomRefreshToken.for_user(User.objects.get(email=user['email']))
            return Response({
                'status': 'success',
                'message': 'Registration successful',
                'data': {
                    'accessToken': str(refresh.access_token),
                    'user': user
                }
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({
                'status': 'error',
                'message': 'Validation failed',
                'errors': [{'field': key, 'message': value[0]} for key, value in e.detail.items()],
                'statusCode': 422
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        except Exception as e:
            return Response({
                'status': 'Bad request',
                'message': 'Registration unsuccessful',
                'statusCode': 400
            }, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        user = authenticate(request, email=email, password=password)
        if user is not None:
            refresh = CustomRefreshToken.for_user(user)
            return Response({
                'status': 'success',
                'message': 'Login successful',
                'data': {
                    'accessToken': str(refresh.access_token),
                    'user': UserSerializer(user).data
                }
            }, status=status.HTTP_200_OK)
        return Response({
            'status': 'Bad request',
            'message': 'Authentication failed',
            'statusCode': 401
        }, status=status.HTTP_401_UNAUTHORIZED)


class UserDetailView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        obj = self.get_queryset().get(pk=self.request.user.pk)
        self.check_object_permissions(self.request, obj)
        return obj


class OrganisationListView(generics.ListAPIView):
    serializer_class = OrganisationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return self.request.user.organisations.all()


class OrganisationDetailView(generics.RetrieveAPIView):
    queryset = Organisation.objects.all()
    serializer_class = OrganisationSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'org_id'

    def get_object(self):
        obj = super().get_object()
        if self.request.user not in obj.users.all():
            raise PermissionDenied("You do not have permission to access this organisation.")
        return obj


class OrganisationCreateView(generics.CreateAPIView):
    serializer_class = OrganisationSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response({
            'status': 'success',
            'message': 'Organisation created successfully',
            'data': serializer.data
        }, status=status.HTTP_201_CREATED)


class AddUserToOrganisationView(generics.GenericAPIView):
    serializer_class = AddUserToOrganisationSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, org_id, *args, **kwargs):
        try:
            organisation = Organisation.objects.get(org_id=org_id)
        except Organisation.DoesNotExist:
            return Response({
                'status': 'Not found',
                'message': 'Organisation not found',
                'statusCode': 404
            }, status=status.HTTP_404_NOT_FOUND)

        user_id = request.data.get('user_id')
        try:
            user = User.objects.get(user_id=user_id)
        except User.DoesNotExist:
            return Response({
                'status': 'Not found',
                'message': 'User not found',
                'statusCode': 404
            }, status=status.HTTP_404_NOT_FOUND)

        # Add the user to the organisation
        organisation.users.add(user)
        return Response({
            'status': 'success',
            'message': 'User added to organisation successfully'
        }, status=status.HTTP_200_OK)
