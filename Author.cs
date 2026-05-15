using System;

namespace Core
{
    public class Author
    {
        public string Name { get; set; }
        public string Country { get; set; }
        public DateTime BirthDate { get; set; }

        public Author(string name, string country, DateTime birthDate)
        {
            Name = name;
            Country = country;
            BirthDate = birthDate;
        }

        public string GetInfo()
        {
            return $"Автор: {Name}, Країна: {Country}, Дата народження: {BirthDate.ToShortDateString()}";
        }
    }
}