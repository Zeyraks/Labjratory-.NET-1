using System;

namespace Core
{
    public class Book
    {
        public string Title { get; set; }
        public int Year { get; set; }
        public double Price { get; set; }
        public bool IsAvailable { get; set; }

        public Book(string title, int year, double price, bool isAvailable)
        {
            Title = title;
            Year = year;
            Price = price;
            IsAvailable = isAvailable;
        }

        public string GetInfo()
        {
            return $"Книга: {Title}, Рік: {Year}, Ціна: {Price}, Доступна: {IsAvailable}";
        }
    }
}