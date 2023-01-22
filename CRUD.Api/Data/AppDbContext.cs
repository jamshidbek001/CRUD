using CRUD.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace CRUD.Api.Data
{
    public class AppDbContext : DbContext
    {
        public DbSet<Team> Teams { get; set; }

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {

        }
    }
}