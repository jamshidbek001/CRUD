﻿using CRUD.Api.Data;
using CRUD.Api.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CRUD.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TeamsController : ControllerBase
    {
        private static AppDbContext _context;

        public TeamsController(AppDbContext context) =>
            _context = context;

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var teams = await _context.Teams.ToListAsync();

            return Ok(teams);
        }

        [HttpGet("{id:int}")]
        public async Task<IActionResult> Get(int id)
        {
            var team = await _context.Teams.FirstOrDefaultAsync(t => t.Id == id);

            if (team == null)
                return BadRequest("Invalid Id");

            return Ok(team);
        }

        [HttpPost]
        public async Task<IActionResult> Post(Team team)
        {
            await _context.Teams.AddAsync(team);
            await _context.SaveChangesAsync();

            return CreatedAtAction("Get", team.Id, team);
        }

        [HttpPatch]
        public async Task<IActionResult> Patch(int id, string country)
        {
            var team = await _context.Teams.FirstOrDefaultAsync(x => x.Id == id);

            if (team == null)
                return BadRequest("Invalid id");

            team.Country = country;
            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete]
        public async Task<IActionResult> Delete(int id)
        {
            var team = await _context.Teams.FirstOrDefaultAsync(x => x.Id == id);

            if (team == null)
                return BadRequest("Invalid id");

            _context.Teams.Remove(team);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}