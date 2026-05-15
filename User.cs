using System;

namespace Core
{
    public class User
    {
        public string Username { get; set; }
        public int Age { get; set; }
        public DateTime RegistrationDate { get; set; }

        public User(string username, int age, DateTime registrationDate)
        {
            Username = username;
            Age = age;
            RegistrationDate = registrationDate;
        }

        public string GetInfo()
        {
            return $"Користувач: {Username}, Вік: {Age}, Дата реєстрації: {RegistrationDate.ToShortDateString()}";
        }
    }
}