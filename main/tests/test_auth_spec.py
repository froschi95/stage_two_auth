from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from main.models import User, Organisation

class RegisterEndpointTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.login_url = reverse('login')

    def test_registration_success(self):
        data = {
            "firstName": "Test",
            "lastName": "User",
            "email": "testuser@example.com",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('accessToken', response.data['data'])
        self.assertEqual(response.data['data']['user']['email'], data['email'])
        self.assertTrue(User.objects.filter(email=data['email']).exists())
        self.assertTrue(Organisation.objects.filter(name="Test's Organisation").exists())

    def test_registration_validation_error(self):
        data = {
            "firstName": "Test",
            "lastName": "User",
            "email": "invalid-email",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')

    def test_registration_database_constraint(self):
        data = {
            "firstName": "Test",
            "lastName": "User",
            "email": "duplicate@example.com",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        User.objects.create_user(
            email="duplicate@example.com",
            firstName="Test",
            lastName="User",
            password="testpassword123"
        )
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')
        self.assertFalse(Organisation.objects.filter(name="Test's Organisation").exists())

    def test_missing_required_firstName(self):
        data = {
            "lastName": "User",
            "email": "testuser@example.com",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')

    def test_missing_required_lastName(self):
        data = {
            "firstName": "User",
            "email": "testuser@example.com",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')

    def test_missing_required_email(self):
        data = {
            "firstName": "Test",
            "lastName": "User",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')

    def test_missing_required_password(self):
        data = {
            "firstName": "Test",
            "lastName": "User",
            "email": "testuser@example.com",
            "phone": "1234567890"
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Validation failed')

    def test_login_success(self):
        registration_data = {
            "firstName": "Test",
            "lastName": "User",
            "email": "testuser@example.com",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        self.client.post(self.register_url, registration_data, format='json')
        
        login_data = {
            "email": "testuser@example.com",
            "password": "testpassword123"
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('accessToken', response.data['data'])

    def test_login_invalid_credentials(self):
        login_data = {
            "email": "nonexistent@example.com",
            "password": "wrongpassword"
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['status'], 'Bad request')
        self.assertEqual(response.data['message'], 'Authentication failed')

class IntegratedWorkflowTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.organisation_create_url = reverse('organisation-create')

    def test_full_workflow(self):
        # Register a new user
        registration_data = {
            "firstName": "Test",
            "lastName": "User",
            "email": "testuser@example.com",
            "password": "testpassword123",
            "phone": "1234567890"
        }
        registration_response = self.client.post(self.register_url, registration_data, format='json')
        self.assertEqual(registration_response.status_code, status.HTTP_201_CREATED)
        access_token = registration_response.data['data']['accessToken']

        # Login with the new user
        login_data = {
            "email": "testuser@example.com",
            "password": "testpassword123"
        }
        login_response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn('accessToken', login_response.data['data'])

        # Create a new organisation
        organisation_data = {
            "name": "Test Organisation"
        }
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        organisation_response = self.client.post(self.organisation_create_url, organisation_data, format='json')
        self.assertEqual(organisation_response.status_code, status.HTTP_201_CREATED)
        # print(organisation_response.data)
        self.assertEqual(organisation_response.data['data']['name'], organisation_data['name'])
