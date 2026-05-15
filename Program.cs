using System;
using System.Text;
using Core;

namespace ConsoleUI
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Author author = new Author("Тарас Шевченко", "Україна", new DateTime(1814, 3, 9));
            Book book = new Book("Кобзар", 1840, 150.5, true);
            User user = new User("Andrey", 20, DateTime.Now);

            Console.WriteLine("=== Онлайн бібліотека ===\n");

            Console.WriteLine(author.GetInfo());
            Console.WriteLine(book.GetInfo());
            Console.WriteLine(user.GetInfo());

            Console.WriteLine("\nНатисніть Enter для виходу...");
            Console.ReadLine();
        }
    }
}