from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from ..models import User, Organisation
# from rest_framework_simplejwt.tokens import RefreshToken
from ..tokens import CustomRefreshToken
from datetime import timedelta
from django.utils import timezone


# Unit Tests
class RegisterEndpointTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_registration_success(self):
        url = reverse('register')
        data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "testuser@example.com",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('accessToken', response.data['data'])
        self.assertEqual(response.data['data']['user']['email'], data['email'])
        self.assertTrue(User.objects.filter(email=data['email']).exists())
        self.assertTrue(Organisation.objects.filter(name="Test's Organisation").exists())

    def test_registration_validation_error(self):
        url = reverse('register')
        data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "invalid-email",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')

    def test_registration_database_constraint(self):
        url = reverse('register')
        data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "duplicate@example.com",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        # Create a user with the same email
        User.objects.create_user(
            email="duplicate@example.com",
            first_name="Test",
            last_name="User",
            password="testpassword123"
        )
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')
        self.assertFalse(Organisation.objects.filter(name="Test's Organisation").exists())

    def test_missing_required_first_name(self):
        url = reverse('register')
        data = {
            "last_name": "User",
            "email": "testuser@example.com",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')
    
    def test_missing_required_last_name(self):
        url = reverse('register')
        data = {
            "first_name": "User",
            "email": "testuser@example.com",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')

    def test_missing_required_email(self):
        url = reverse('register')
        data = {
            "last_name": "User",
            "first_name": "tOne",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')

    def test_missing_required_password(self):
        url = reverse('register')
        data = {
            "last_name": "User",
            "first_name": "tOne",
            "email": "testuser@example.com",
            "phone": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')


class LoginEndpointTests(APITestCase):

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="testuser@example.com",
            first_name="Test",
            last_name="User",
            password="testpassword123"
        )

    def test_successful_login(self):
        url = reverse('login')
        data = {
            "email": "testuser@example.com",
            "password": "testpassword123"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('accessToken', response.data['data'])
        self.assertEqual(response.data['data']['user']['email'], data['email'])

    def test_failed_login(self):
        url = reverse('login')
        data = {
            "email": "testuser@example.com",
            "password": "wrongpassword"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['status'], 'Bad request')
        self.assertEqual(response.data['message'], 'Authentication failed')


class TokenGenerationTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email="testuser@example.com",
            first_name="Test",
            last_name="User",
            password="testpassword123"
        )

    def test_token_generation(self):
        refresh = CustomRefreshToken.for_user(self.user)
        # print(refresh.payload)
        # print(refresh.access_token.payload)
        self.assertIsNotNone(refresh.access_token)
        self.assertEqual((refresh.access_token['user_id']), str(self.user.user_id))

    def test_token_expiration(self):
        refresh = CustomRefreshToken.for_user(self.user)
        access_token = refresh.access_token
        # Assuming token lifetime is 5 minutes by default
        self.assertLessEqual(refresh.access_token.lifetime.total_seconds(), 300)

    def test_token_user_details(self):
        refresh = CustomRefreshToken.for_user(self.user)
        access_token = refresh.access_token
        
        # Ensure access token is valid and has necessary attributes
        self.assertTrue(access_token)
        self.assertTrue(hasattr(access_token, 'payload'))
        # print(access_token.payload)

        # Access attributes from the token payload directly
        self.assertEqual(str(access_token.payload['user_id']), str(self.user.user_id))
        # self.assertEqual(access_token.payload['email'], self.user.email)
        # self.assertEqual(access_token.payload['first_name'], self.user.first_name)


class OrganisationAccessTests(APITestCase):

    def setUp(self):
        self.client = APIClient()
        self.user1 = User.objects.create_user(
            email="user1@example.com",
            first_name="User1",
            last_name="One",
            password="password123"
        )
        self.user2 = User.objects.create_user(
            email="user2@example.com",
            first_name="User2",
            last_name="Two",
            password="password123"
        )
        self.org1 = Organisation.objects.create(name="User1's Organisation")
        self.org1.users.set([self.user1])
        self.org2 = Organisation.objects.create(name="User2's Organisation")
        self.org2.users.set([self.user2])

    def test_organisation_access(self):
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(reverse('organisation-list'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check that user1 can only see org1
        org_ids = [org['org_id'] for org in response.data]
        self.assertIn(str(self.org1.org_id), org_ids)
        self.assertNotIn(str(self.org2.org_id), org_ids)

    def test_organisation_access_forbidden(self):
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(reverse('organisation-detail', kwargs={'org_id': str(self.org2.org_id)}))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# E2E Tests
class UserAuthE2ETest(APITestCase):

    @classmethod
    def setUpTestData(cls):
        cls.client = APIClient()
        cls.register_url = reverse('register')
        cls.login_url = reverse('login')
        cls.create_org_url = reverse('organisation-create')
        cls.user_data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'password': 'password123',
            'phone': '1234567890'
        }
        cls.org_data = {
            'name': 'Test Org',
            'description': 'A test organization'
        }

    def register_user(self):
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def login_user(self):
        response = self.client.post(self.login_url, {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('accessToken', response.data['data'])
        return response.data['data']['accessToken']

    def create_organisation(self, token):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)
        response = self.client.post(self.create_org_url, self.org_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        return response.data['data']['org_id']

    def test_user_registration_and_login(self):
        self.register_user()
        self.login_user()

    def test_create_organisation_and_add_user(self):
        self.register_user()
        token = self.login_user()
        org_id = self.create_organisation(token)

        # Check if user exists
        user = User.objects.get(email=self.user_data['email'])
        add_user_url = reverse('add-user-to-organisation', kwargs={'org_id': org_id})
        add_user_data = {
            'user_id': str(user.user_id)
        }
        response = self.client.post(add_user_url, add_user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)